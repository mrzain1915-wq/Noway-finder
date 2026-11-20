"""Local-only web workspace and versioned JSON API; public server exposure is disabled."""

import asyncio
import json
import secrets
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .domains import import_hosts
from .engine import Controller, Engine
from .export import export_job
from .models import Config, Filter
from .update import update_prefixes


def filters_from_query(query: dict) -> Filter:
    def val(name, default=""):
        return query.get(name, [default])[0]

    return Filter(
        query=val("q"),
        provider=val("provider"),
        scope=val("scope"),
        confidence=val("confidence"),
        alive_only=val("alive") == "1",
        cdn_only=val("cdn") == "1",
        include_wildcard=val("wildcard") == "1",
        status=int(val("status")) if val("status") else None,
        family=int(val("family", "0")),
    )


class FinderServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, store, port=8765, controller=None):
        self.store = store
        self.controller = controller or Controller(store)
        self.token = secrets.token_hex(32)
        super().__init__(("127.0.0.1", port), Handler)
        self.store.recover()


class Handler(BaseHTTPRequestHandler):
    server_version = "NOWAYFinder/1.0"

    def log_message(self, *_):
        pass

    def send_bytes(self, data: bytes, content_type="application/json; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
        )
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, data, status=200):
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode(), status=status)

    def guard(self, mutation=False):
        port = self.server.server_address[1]
        if self.headers.get("Host", "") not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
            raise PermissionError("Unexpected Host header")
        if mutation and not secrets.compare_digest(self.headers.get("X-Noway-Token", ""), self.server.token):
            raise PermissionError("Missing or invalid workspace token")
        origin = self.headers.get("Origin")
        if origin and origin not in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}:
            raise PermissionError("Cross-origin requests are not supported")

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 20 * 1024 * 1024:
            raise ValueError("Request body must be 1 byte to 20 MiB")
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def dispatch(self, method):
        self.guard(method != "GET")
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        store, controller = self.server.store, self.server.controller
        parts = path.strip("/").split("/")
        if method == "GET":
            if path in {"/", "/app.js", "/style.css"}:
                name = "index.html" if path == "/" else path[1:]
                data = files("noway_finder").joinpath("web/" + name).read_bytes()
                if name == "app.js":
                    data = data.replace(b"__NOWAY_TOKEN__", self.server.token.encode())
                mime = {"index.html": "text/html", "app.js": "text/javascript", "style.css": "text/css"}[name]
                self.send_bytes(data, mime + "; charset=utf-8")
                return
            if path == "/api/status":
                self.send_json(
                    {
                        "schema": 1,
                        "version": __version__,
                        "jobs": store.jobs(),
                        "active_job": controller.active_id if controller.active else None,
                    }
                )
                return
            if path == "/api/profiles":
                self.send_json(store.profiles())
                return
            if path == "/api/compare":
                self.send_json(store.compare(int(query["first"][0]), int(query["second"][0])))
                return
            if len(parts) >= 3 and parts[:2] == ["api", "jobs"]:
                job_id = int(parts[2])
                store.job(job_id)
                if len(parts) == 3:
                    self.send_json(store.job(job_id))
                    return
                if parts[3] == "results":
                    self.send_json(
                        store.page(
                            job_id,
                            filters_from_query(query),
                            int(query.get("offset", [0])[0]),
                            int(query.get("limit", [100])[0]),
                        )
                    )
                    return
                if parts[3] == "export":
                    fmt = query.get("format", ["csv"])[0]
                    with tempfile.TemporaryDirectory(prefix="noway-download-") as folder:
                        file = export_job(
                            store,
                            job_id,
                            Path(folder) / "report",
                            fmt,
                            filters_from_query(query),
                            query.get("txt_field", ["hostname"])[0],
                        )
                        self.send_response(200)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Length", str(file.stat().st_size))
                        self.send_header(
                            "Content-Disposition", f'attachment; filename="NOWAY-Finder-job-{job_id}.{fmt}"'
                        )
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.end_headers()
                        with file.open("rb") as stream:
                            while chunk := stream.read(65536):
                                self.wfile.write(chunk)
                    return
        elif method == "POST":
            data = self.body()
            if path == "/api/queue/start":
                queued = sorted(j["id"] for j in store.jobs() if j["state"] == "queued")
                if not queued:
                    raise ValueError("No queued jobs")
                controller.start(queued[0], run_queue=True)
                self.send_json({"ok": True})
                return
            if path == "/api/import":
                hosts, errors = import_hosts(str(data.get("text", "")))
                self.send_json({"hosts": hosts, "invalid": errors[:100], "invalid_count": len(errors)})
                return
            if path == "/api/jobs":
                job_id = Engine(store).create(Config.from_dict(data))
                self.send_json({"job": job_id}, 201)
                return
            if path == "/api/profiles":
                store.save_profile(str(data["name"])[:100], Config.from_dict(data["config"]))
                self.send_json({"saved": True})
                return
            if path == "/api/update-data":
                self.send_json(asyncio.run(update_prefixes(store)))
                return
            if len(parts) == 4 and parts[:2] == ["api", "jobs"]:
                job_id = int(parts[2])
                if parts[3] in {"start", "resume"}:
                    controller.start(job_id)
                elif parts[3] in {"pause", "stop"}:
                    if controller.active_id != job_id:
                        raise ValueError("This job is not active")
                    controller.pause(stop=parts[3] == "stop")
                else:
                    raise ValueError("Unknown action")
                self.send_json({"ok": True})
                return
        elif method == "DELETE" and len(parts) == 3 and parts[:2] == ["api", "jobs"]:
            job_id = int(parts[2])
            if controller.active and controller.active_id == job_id:
                raise ValueError("Stop this job before deleting it")
            store.job(job_id)
            with store.transaction() as db:
                db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
            self.send_json({"deleted": True})
            return
        self.send_json({"error": "Not found"}, 404)

    def handle_request(self, method):
        try:
            self.dispatch(method)
        except PermissionError as error:
            self.send_json({"error": str(error)}, 403)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            self.send_json({"error": str(error)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            self.send_json({"error": f"Request failed: {type(error).__name__}"}, 500)

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def do_DELETE(self):
        self.handle_request("DELETE")
