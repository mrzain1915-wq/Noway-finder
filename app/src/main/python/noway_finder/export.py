"""Streaming full-dataset exports, formula-safe CSV and portable ZIP evidence reports."""

import csv
import hashlib
import html
import json
import tempfile
import zipfile
from pathlib import Path

from .models import Filter, utc_now

FORMATS = {"csv", "txt", "json", "jsonl", "html", "md", "zip"}
COLUMNS = [
    "hostname",
    "root",
    "scope",
    "provider",
    "confidence",
    "hosting",
    "ips",
    "cnames",
    "asns",
    "status",
    "latency_ms",
    "sources",
    "connections",
    "evidence",
    "errors",
    "checked_at",
    "record_state",
]


def cell(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    value = "" if value is None else str(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def export_job(
    store,
    job_id: int,
    output: str | Path,
    fmt="csv",
    filters: Filter | None = None,
    txt_field="hostname",
    _snapshot=True,
) -> Path:
    if fmt not in FORMATS:
        raise ValueError("Unsupported export format")
    if txt_field not in {"hostname", "root", "ips"}:
        raise ValueError("TXT field must be hostname, root or ips")
    if _snapshot:
        from .store import Store

        with tempfile.TemporaryDirectory(prefix="noway-snapshot-") as folder:
            snapshot = Store(Path(folder) / "snapshot.sqlite3")
            try:
                store.backup(snapshot)
                return export_job(snapshot, job_id, output, fmt, filters, txt_field, False)
            finally:
                snapshot.close()
    job = store.job(job_id)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "zip":
        with tempfile.TemporaryDirectory(prefix="noway-export-") as temp:
            generated = []
            for name in sorted(FORMATS - {"zip"}):
                generated.append(
                    export_job(
                        store, job_id, Path(temp) / f"findings.{name}", name, filters, txt_field, False
                    )
                )
            manifest = {
                "schema": 1,
                "tool": "NOWAY Finder 1.0.0",
                "job": job_id,
                "exported_at": utc_now(),
                "job_state": job["state"],
                "filters": vars(filters or Filter()),
                "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in generated},
            }
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                for p in generated:
                    archive.write(p, p.name)
                archive.writestr("manifest.json", json.dumps(manifest, indent=2))
        return output
    with output.open("w", encoding="utf-8", newline="") as stream:
        if fmt == "csv":
            writer = csv.writer(stream)
            writer.writerow(COLUMNS)
            for row in store.rows(job_id, filters):
                writer.writerow([cell(row.get(key)) for key in COLUMNS])
        elif fmt == "txt":
            seen = set()
            for row in store.rows(job_id, filters):
                values = row["ips"] if txt_field == "ips" else [row[txt_field]]
                for value in values:
                    if value and value not in seen:
                        seen.add(value)
                        stream.write(value + "\n")
        elif fmt in {"json", "jsonl"}:
            if fmt == "json":
                stream.write("[\n")
            first = True
            for row in store.rows(job_id, filters):
                if fmt == "json" and not first:
                    stream.write(",\n")
                stream.write(json.dumps(row, ensure_ascii=False))
                if fmt == "jsonl":
                    stream.write("\n")
                first = False
            if fmt == "json":
                stream.write("\n]\n")
        elif fmt == "html":
            stream.write(
                '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" '
                'content="width=device-width"><title>NOWAY Finder report</title><style>'
                "body{background:#0B1120;color:#E5E7EB;font:15px system-ui;padding:24px}"
                "h1{color:#34D399}table{border-collapse:collapse;width:100%}"
                "td,th{padding:10px;border:1px solid #334155;text-align:left;overflow-wrap:anywhere}"
                "</style><h1>NOWAY Finder</h1><p>Relationships describe observed links; "
                "they do not establish common ownership.</p><table><thead><tr>"
            )
            fields = ("hostname", "scope", "provider", "confidence", "ips", "sources")
            stream.write("".join("<th>" + html.escape(k) + "</th>" for k in fields) + "</tr></thead><tbody>")
            for row in store.rows(job_id, filters):
                stream.write(
                    "<tr>"
                    + "".join("<td>" + html.escape(str(row.get(k, ""))) + "</td>" for k in fields)
                    + "</tr>\n"
                )
            stream.write("</tbody></table></html>")
        elif fmt == "md":
            stream.write("# NOWAY Finder\n\n| Hostname | Scope | CDN | Confidence |\n|---|---|---|---|\n")
            for row in store.rows(job_id, filters):
                stream.write(
                    "| "
                    + " | ".join(
                        str(row.get(k, "")).replace("|", "\\|").replace("\n", " ")
                        for k in ("hostname", "scope", "provider", "confidence")
                    )
                    + " |\n"
                )
    return output
