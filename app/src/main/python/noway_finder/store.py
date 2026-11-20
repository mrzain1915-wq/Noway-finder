"""SQLite WAL job queue, atomic evidence records and indexed full-result queries."""

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .models import Config, Filter, Finding, utc_now


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
              id INTEGER PRIMARY KEY AUTOINCREMENT, config TEXT NOT NULL,
              state TEXT NOT NULL, phase TEXT NOT NULL DEFAULT 'discovery',
              created TEXT NOT NULL, updated TEXT NOT NULL, warnings TEXT NOT NULL DEFAULT '[]',
              in_count INTEGER NOT NULL DEFAULT 0, related_count INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS hosts (
              job INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, hostname TEXT NOT NULL,
              root TEXT NOT NULL, scope TEXT NOT NULL, depth INTEGER NOT NULL DEFAULT 0,
              state TEXT NOT NULL DEFAULT 'pending', provider TEXT NOT NULL DEFAULT 'Unknown',
              confidence TEXT NOT NULL DEFAULT 'unknown', status INTEGER, alive INTEGER NOT NULL DEFAULT 0,
              wildcard INTEGER NOT NULL DEFAULT 0, family4 INTEGER NOT NULL DEFAULT 0,
              family6 INTEGER NOT NULL DEFAULT 0, sources TEXT NOT NULL DEFAULT '[]',
              links TEXT NOT NULL DEFAULT '[]', result TEXT, PRIMARY KEY(job,hostname));
            CREATE INDEX IF NOT EXISTS host_state ON hosts(job,state,scope);
            CREATE INDEX IF NOT EXISTS host_provider ON hosts(job,provider,confidence);
            CREATE TABLE IF NOT EXISTS cache (
              key TEXT PRIMARY KEY, expires REAL NOT NULL, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS profiles (
              name TEXT PRIMARY KEY, config TEXT NOT NULL);
            PRAGMA user_version=1;
        """)
        self.db.commit()

    @contextmanager
    def transaction(self):
        with self.lock:
            outer = not self.db.in_transaction
            if outer:
                self.db.execute("BEGIN")
            try:
                yield self.db
            except BaseException:
                if outer:
                    self.db.rollback()
                raise
            else:
                if outer:
                    self.db.commit()

    def close(self):
        with self.lock:
            self.db.close()

    def create(self, config: Config) -> int:
        now = utc_now()
        with self.transaction() as db:
            cur = db.execute(
                "INSERT INTO jobs(config,state,created,updated) VALUES(?,?,?,?)",
                (json.dumps(config.to_dict()), "queued", now, now),
            )
            return cur.lastrowid

    def job(self, job_id: int) -> dict:
        with self.lock:
            row = self.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise ValueError("Job not found")
            result = dict(row)
            result["config"] = json.loads(result["config"])
            result["warnings"] = json.loads(result["warnings"])
            stats = self.db.execute(
                """SELECT COUNT(*) total,
              COALESCE(SUM(state='done'),0) checked, COALESCE(SUM(scope='in_scope'),0) in_scope,
              COALESCE(SUM(scope='related'),0) related,
              COALESCE(SUM(provider!='Unknown'),0) cdn,
              COALESCE(SUM(wildcard),0) wildcard FROM hosts WHERE job=?""",
                (job_id,),
            ).fetchone()
            result.update(dict(stats))
            return result

    def jobs(self) -> list[dict]:
        with self.lock:
            ids = [r[0] for r in self.db.execute("SELECT id FROM jobs ORDER BY id DESC")]
            return [self.job(job_id) for job_id in ids]

    def state(self, job_id: int, state: str, phase: str | None = None):
        if state not in {"queued", "running", "paused", "stopped", "completed", "failed"}:
            raise ValueError("Invalid job state")
        with self.transaction() as db:
            if phase is None:
                db.execute("UPDATE jobs SET state=?,updated=? WHERE id=?", (state, utc_now(), job_id))
            else:
                db.execute(
                    "UPDATE jobs SET state=?,phase=?,updated=? WHERE id=?", (state, phase, utc_now(), job_id)
                )

    def recover(self):
        with self.transaction() as db:
            db.execute("UPDATE jobs SET state='paused' WHERE state='running'")
            db.execute("UPDATE hosts SET state='pending' WHERE state='working'")

    def warning(self, job_id: int, message: str):
        with self.transaction() as db:
            warnings = self.job(job_id)["warnings"]
            if message[:300] not in warnings and len(warnings) < 100:
                warnings.append(message[:300])
            db.execute("UPDATE jobs SET warnings=? WHERE id=?", (json.dumps(warnings), job_id))

    def add(
        self,
        job_id: int,
        host: str,
        root: str,
        scope: str,
        source: str,
        parent: str = "",
        relation: str = "",
        depth: int = 0,
        limit: int = 10000,
    ) -> bool:
        with self.transaction() as db:
            old = db.execute(
                "SELECT sources,links FROM hosts WHERE job=? AND hostname=?", (job_id, host)
            ).fetchone()
            sources = json.loads(old[0]) if old else []
            links = json.loads(old[1]) if old else []
            if source and source not in sources and len(sources) < 30:
                sources.append(source)
            link = {"from": parent, "relation": relation, "source": source}
            if parent and link not in links and len(links) < 100:
                links.append(link)
            if old:
                db.execute(
                    "UPDATE hosts SET sources=?,links=? WHERE job=? AND hostname=?",
                    (json.dumps(sources), json.dumps(links), job_id, host),
                )
                return False
            column = "in_count" if scope == "in_scope" else "related_count"
            count = db.execute(f"SELECT {column} FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
            if count >= limit:
                return False
            db.execute(
                """INSERT INTO hosts(job,hostname,root,scope,depth,sources,links)
                       VALUES(?,?,?,?,?,?,?)""",
                (job_id, host, root, scope, depth, json.dumps(sources), json.dumps(links)),
            )
            db.execute(f"UPDATE jobs SET {column}={column}+1 WHERE id=?", (job_id,))
            return True

    def claim(self, job_id: int, related: bool = False) -> dict | None:
        with self.transaction() as db:
            sql = "SELECT * FROM hosts WHERE job=? AND state='pending'"
            if not related:
                sql += " AND scope='in_scope'"
            row = db.execute(sql + " ORDER BY depth,hostname LIMIT 1", (job_id,)).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE hosts SET state='working' WHERE job=? AND hostname=?", (job_id, row["hostname"])
            )
            return dict(row)

    def complete(self, job_id: int, finding: Finding):
        with self.transaction() as db:
            db.execute(
                """UPDATE hosts SET state='done',provider=?,confidence=?,status=?,alive=?,
              wildcard=?,family4=?,family6=?,result=? WHERE job=? AND hostname=?""",
                (
                    finding.provider,
                    finding.confidence,
                    finding.status,
                    bool(finding.ips or finding.status),
                    finding.wildcard,
                    any(":" not in ip for ip in finding.ips),
                    any(":" in ip for ip in finding.ips),
                    json.dumps(finding.to_dict(), ensure_ascii=False),
                    job_id,
                    finding.hostname,
                ),
            )

    def release_claims(self, job_id: int):
        with self.transaction() as db:
            db.execute("UPDATE hosts SET state='pending' WHERE job=? AND state='working'", (job_id,))

    def remaining(self, job_id: int, related=False) -> int:
        with self.lock:
            sql = "SELECT COUNT(*) FROM hosts WHERE job=? AND state IN ('pending','working')"
            if not related:
                sql += " AND scope='in_scope'"
            return self.db.execute(sql, (job_id,)).fetchone()[0]

    def backup(self, other):
        with self.lock, other.lock:
            self.db.backup(other.db)

    @staticmethod
    def _where(job_id: int, filters: Filter):
        clauses, args = ["job=?"], [job_id]
        for key in ("provider", "scope", "confidence", "status"):
            value = getattr(filters, key)
            if value is not None and value != "":
                clauses.append(f"{key}=?")
                args.append(value)
        if filters.query:
            escaped = filters.query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(hostname LIKE ? ESCAPE '\\' OR provider LIKE ? ESCAPE '\\')")
            args.extend([f"%{escaped}%"] * 2)
        if filters.alive_only:
            clauses.append("alive=1")
        if filters.cdn_only:
            clauses.append("provider!='Unknown'")
        if not filters.include_wildcard:
            clauses.append("wildcard=0")
        if filters.family:
            clauses.append(f"family{filters.family}=1")
        return " AND ".join(clauses), args

    def page(self, job_id: int, filters: Filter | None = None, offset=0, limit=100) -> dict:
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("Invalid page bounds")
        where, args = self._where(job_id, filters or Filter())
        with self.lock:
            total = self.db.execute("SELECT COUNT(*) FROM hosts WHERE " + where, args).fetchone()[0]
            rows = self.db.execute(
                "SELECT * FROM hosts WHERE " + where + " ORDER BY hostname LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
            return {"total": total, "offset": offset, "limit": limit, "rows": [self._row(r) for r in rows]}

    @staticmethod
    def _row(row) -> dict:
        result = (
            json.loads(row["result"])
            if row["result"]
            else Finding(row["hostname"], row["root"], row["scope"]).to_dict()
        )
        result["sources"] = json.loads(row["sources"])
        result["connections"] = json.loads(row["links"])
        result["record_state"] = row["state"]
        return result

    def rows(self, job_id: int, filters: Filter | None = None):
        offset = 0
        while True:
            page = self.page(job_id, filters, offset, 1000)
            yield from page["rows"]
            offset += len(page["rows"])
            if not page["rows"]:
                break

    def cache_get(self, key: str):
        with self.lock:
            row = self.db.execute(
                "SELECT value FROM cache WHERE key=? AND expires>?", (key, time.time())
            ).fetchone()
            return json.loads(row[0]) if row else None

    def cache_put(self, key: str, value, ttl=3600):
        with self.transaction() as db:
            db.execute(
                "INSERT OR REPLACE INTO cache VALUES(?,?,?)", (key, time.time() + ttl, json.dumps(value))
            )
            db.execute("DELETE FROM cache WHERE expires<?", (time.time(),))

    def profiles(self) -> dict:
        with self.lock:
            return {
                r[0]: json.loads(r[1])
                for r in self.db.execute("SELECT name,config FROM profiles ORDER BY name")
            }

    def save_profile(self, name: str, config: Config):
        if not name.strip() or len(name) > 80:
            raise ValueError("Profile name must contain 1–80 characters")
        with self.transaction() as db:
            db.execute(
                "INSERT OR REPLACE INTO profiles VALUES(?,?)", (name.strip(), json.dumps(config.to_dict()))
            )

    def delete(self, job_id: int):
        with self.transaction() as db:
            db.execute("DELETE FROM hosts WHERE job=?", (job_id,))
            db.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    def compare(self, first: int, second: int) -> dict:
        self.job(first)
        self.job(second)
        old = {r["hostname"]: r["provider"] for r in self.rows(first)}
        new = {r["hostname"]: r["provider"] for r in self.rows(second)}
        return {
            "added": sorted(new.keys() - old.keys()),
            "removed": sorted(old.keys() - new.keys()),
            "provider_changed": [
                {"hostname": h, "before": old[h], "after": new[h]}
                for h in sorted(old.keys() & new.keys())
                if old[h] != new[h]
            ],
        }
