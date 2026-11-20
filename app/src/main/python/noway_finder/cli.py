"""NOWAY Finder CLI and optional local workspace; no network traffic on import."""

import argparse
import asyncio
import json
import signal
import sys
from pathlib import Path

from . import __version__
from .domains import import_hosts, normalize_roots
from .engine import Engine
from .export import FORMATS, export_job
from .models import Config, Filter
from .service import FinderServer
from .store import Store
from .update import update_prefixes


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="noway-finder", description="NOWAY Finder — domain discovery and CDN evidence"
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--database", default=str(Path.home() / ".noway-finder" / "finder.sqlite3"))
    sub = parser.add_subparsers(dest="command", required=True)
    find = sub.add_parser("find", help="Discover and optionally verify domains")
    find.add_argument("domains", nargs="*")
    find.add_argument("--input", type=Path, help="TXT/CSV root domain list")
    find.add_argument("--seeds", type=Path, help="TXT/CSV known hosts to add under the supplied roots")
    find.add_argument("--mode", choices=["discover", "verify"], default="verify")
    find.add_argument("--no-ct", action="store_true")
    find.add_argument("--commoncrawl", action="store_true")
    find.add_argument("--wordlist", nargs="?", const="builtin")
    find.add_argument("--no-related", action="store_true")
    find.add_argument("--probe-related", action="store_true")
    find.add_argument("--no-asn", action="store_true")
    find.add_argument("--workers", type=int, default=32)
    find.add_argument("--rate", type=float, default=30)
    find.add_argument("--timeout", type=float, default=8)
    find.add_argument("--retries", type=int, default=1)
    find.add_argument("--max-hosts", type=int, default=10000)
    find.add_argument("--max-related", type=int, default=2000)
    find.add_argument("--depth", type=int, default=2)
    find.add_argument("--max-pages", type=int, default=20)
    find.add_argument("--source-pages", type=int, default=3)
    find.add_argument("--dns-server", action="append", default=[])
    find.add_argument(
        "--insecure-tls", action="store_true", help="Explicit TLS inspection without certificate verification"
    )
    find.add_argument(
        "--allow-private", action="store_true", help="Allow private-address endpoints for local/lab targets"
    )
    find.add_argument("--rules", help="Validated custom provider-rule JSON")
    find.add_argument("--output", type=Path)
    find.add_argument("--format", choices=sorted(FORMATS), default="csv")
    sub.add_parser("jobs")
    resume = sub.add_parser("resume")
    resume.add_argument("job", type=int)
    export = sub.add_parser("export")
    export.add_argument("job", type=int)
    export.add_argument("output", type=Path)
    export.add_argument("--format", choices=sorted(FORMATS), default="csv")
    export.add_argument("--provider", default="")
    export.add_argument("--scope", choices=["", "in_scope", "related"], default="")
    export.add_argument("--query", default="")
    export.add_argument("--alive", action="store_true")
    export.add_argument("--cdn-only", action="store_true")
    export.add_argument("--txt-field", choices=["hostname", "root", "ips"], default="hostname")
    compare = sub.add_parser("compare")
    compare.add_argument("first", type=int)
    compare.add_argument("second", type=int)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=8765)
    sub.add_parser("update-data", help="Refresh official Cloudflare/Fastly network prefixes")
    args = parser.parse_args(argv)
    store = Store(Path(args.database).expanduser())
    controller = None
    try:
        if args.command == "jobs":
            print(json.dumps(store.jobs(), indent=2))
        elif args.command == "compare":
            print(json.dumps(store.compare(args.first, args.second), indent=2))
        elif args.command == "update-data":
            print(json.dumps(asyncio.run(update_prefixes(store)), indent=2))
        elif args.command == "export":
            result = export_job(
                store,
                args.job,
                args.output,
                args.format,
                Filter(
                    query=args.query,
                    provider=args.provider,
                    scope=args.scope,
                    alive_only=args.alive,
                    cdn_only=args.cdn_only,
                ),
                args.txt_field,
            )
            print(str(result.resolve()))
        elif args.command == "serve":
            server = FinderServer(store, args.port)
            controller = server.controller
            print(f"NOWAY Finder {__version__}: http://127.0.0.1:{server.server_address[1]}", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        elif args.command in {"find", "resume"}:
            store.recover()
            engine = Engine(store, rules_path=getattr(args, "rules", None))
            if args.command == "find":
                roots = list(args.domains)
                if args.input:
                    imported, invalid = import_hosts(args.input.read_text(encoding="utf-8-sig"))
                    roots.extend(imported)
                    if invalid:
                        print(f"Skipped {len(invalid)} invalid input values", file=sys.stderr)
                seeds = import_hosts(args.seeds.read_text(encoding="utf-8-sig"))[0] if args.seeds else []
                words = (
                    ()
                    if args.wordlist in {None, "builtin"}
                    else tuple(Path(args.wordlist).read_text(encoding="utf-8-sig").splitlines())
                )
                config = Config(
                    roots=normalize_roots(roots),
                    seeds=tuple(seeds),
                    mode=args.mode,
                    ct=not args.no_ct,
                    commoncrawl=args.commoncrawl,
                    wordlist=args.wordlist is not None,
                    custom_words=words,
                    related=not args.no_related,
                    asn=not args.no_asn,
                    workers=args.workers,
                    rate=args.rate,
                    timeout=args.timeout,
                    retries=args.retries,
                    max_hosts=args.max_hosts,
                    max_related=args.max_related,
                    max_depth=args.depth,
                    max_pages=args.max_pages,
                    source_pages=args.source_pages,
                    verify_tls=not args.insecure_tls,
                    allow_private=args.allow_private,
                    probe_related=args.probe_related,
                    dns_servers=tuple(args.dns_server),
                )
                job_id = engine.create(config)
            else:
                job_id = args.job
            print(f"NOWAY Finder job {job_id}", flush=True)

            async def run():
                loop = asyncio.get_running_loop()
                task = asyncio.create_task(engine.run(job_id))
                # SIGINT requests a durable pause rather than deleting partial findings.
                try:
                    loop.add_signal_handler(signal.SIGINT, task.cancel)
                except (NotImplementedError, RuntimeError):
                    pass
                await task

            asyncio.run(run())
            result = store.job(job_id)
            print(json.dumps(result, indent=2))
            if args.command == "find" and args.output:
                export_job(store, job_id, args.output, args.format)
            return 1 if result["state"] == "failed" else 0
        return 0
    except (ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    finally:
        if controller and controller.active:
            controller.pause(stop=True)
            controller.wait(10)
        store.close()
