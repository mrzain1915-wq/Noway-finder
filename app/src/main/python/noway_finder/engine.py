"""Resumable multi-source discovery and bounded async verification pipeline."""

import asyncio
import json
import secrets
import threading
from importlib.resources import files

from .detect import Detector
from .domains import (
    certificate_names,
    hostname,
    html_hosts,
    matching_root,
    registered_domain,
    try_host,
    valid_word,
)
from .models import Config, Finding
from .network import Network


class Engine:
    def __init__(self, store, network_factory=Network, rules_path=None):
        self.store = store
        self.network_factory = network_factory
        self.rules_path = rules_path
        self.pause_requested = threading.Event()
        self.stop_requested = threading.Event()
        self.on_event = lambda event: None

    def create(self, config: Config) -> int:
        normalized = tuple(dict.fromkeys(hostname(root) for root in config.roots))
        config = Config.from_dict({**config.to_dict(), "roots": normalized})
        return self.store.create(config)

    async def run(self, job_id: int):
        job = self.store.job(job_id)
        if job["state"] == "completed":
            return
        config = Config.from_dict(job["config"])
        self.pause_requested.clear()
        self.stop_requested.clear()
        network = self.network_factory(config, self.store)
        cached = self.store.cache_get("published_prefixes") or {}
        detector = Detector(self.rules_path, cached)
        pages = 0
        wildcard: dict[str, set[str]] = {}

        def add(host, source, parent="", relation="", depth=0, root_hint=""):
            if not (host := try_host(host)):
                return
            root = matching_root(host, config.roots)
            scope = "in_scope" if root else "related"
            if scope == "related" and not config.related:
                return
            cap = config.max_hosts if root else config.max_related
            added = self.store.add(
                job_id,
                host,
                root or root_hint or config.roots[0],
                scope,
                source,
                parent,
                relation,
                depth,
                cap,
            )
            if added:
                self.on_event({"event": "discovered", "job": job_id, "hostname": host, "scope": scope})
            if scope == "related":
                apex = registered_domain(host)
                if apex != host:
                    self.store.add(
                        job_id,
                        apex,
                        root_hint or config.roots[0],
                        "related",
                        source,
                        host,
                        "registrable_domain",
                        depth,
                        config.max_related,
                    )

        async def bounded(items, operation):
            iterator = iter(items)

            async def worker():
                while True:
                    try:
                        item = next(iterator)
                    except StopIteration:
                        return
                    await operation(item)

            await asyncio.gather(*(worker() for _ in range(config.workers)))

        async def source(root, label, operation):
            try:
                await operation()
            except (OSError, ValueError, RuntimeError, TimeoutError) as error:
                self.store.warning(job_id, f"{label} ({root}): {str(error)[:160]}")
            except Exception as error:
                self.store.warning(job_id, f"{label} ({root}): {type(error).__name__}")

        async def ct(root):
            raw = await network.public_api("https://crt.sh/", {"q": "%." + root, "output": "json"})
            records = json.loads(raw)
            if not isinstance(records, list):
                raise ValueError("Unexpected certificate-log response")
            for record in records:
                for host, is_pattern in certificate_names(str(record.get("name_value", ""))):
                    if matching_root(host, (root,)):
                        add(
                            host,
                            "certificate_transparency",
                            root,
                            "certificate_wildcard_pattern" if is_pattern else "certificate_name",
                            1,
                            root,
                        )

        async def crawl(root):
            collections = json.loads(await network.public_api("https://index.commoncrawl.org/collinfo.json"))
            if not isinstance(collections, list) or not collections:
                raise ValueError("No Common Crawl collections available")
            endpoint = str(collections[0].get("cdx-api", ""))
            if not endpoint.startswith("https://index.commoncrawl.org/"):
                raise ValueError("Unexpected Common Crawl endpoint")
            params = {"url": "*." + root, "output": "json", "collapse": "urlkey", "pageSize": 2}
            info = json.loads(await network.public_api(endpoint, {**params, "showNumPages": "true"}))
            pages_available = max(0, int(info.get("pages", 0)))
            for index in range(min(config.source_pages, pages_available)):
                raw = await network.public_api(endpoint, {**params, "page": index}, cache_ttl=86400)
                for line in raw.splitlines():
                    if not line.strip():
                        continue
                    host = try_host(json.loads(line).get("url", ""))
                    if host and matching_root(host, (root,)):
                        add(host, "common_crawl", root, "archived_url", 1, root)
            if pages_available > config.source_pages:
                self.store.warning(
                    job_id,
                    f"Common Crawl ({root}): {config.source_pages}/{pages_available} pages read; increase source_pages for more",
                )

        async def wildcard_ips(root):
            if root not in wildcard:
                answers = []
                for _ in range(3):
                    try:
                        answers.append(set(await network.addresses(f"nf-{secrets.token_hex(8)}.{root}")))
                    except (OSError, RuntimeError, TimeoutError):
                        answers.append(set())
                wildcard[root] = set.intersection(*answers) if all(answers) else set()
            return wildcard[root]

        async def word(root):
            base = files("noway_finder").joinpath("data/wordlist.txt").read_text().splitlines()
            words = list(dict.fromkeys([*base, *config.custom_words]))
            baseline = await wildcard_ips(root)

            async def check(prefix):
                if not valid_word(prefix):
                    return
                host = try_host(prefix + "." + root)
                if not host:
                    return
                try:
                    ips = set(await network.addresses(host))
                    if ips and not (baseline and ips & baseline):
                        add(host, "dns_wordlist", root, "resolved_subdomain", 1, root)
                except (OSError, RuntimeError, TimeoutError):
                    pass

            await bounded(words, check)
            if baseline:
                self.store.warning(
                    job_id, f"Wildcard DNS found at {root}; matching wordlist guesses were removed"
                )

        async def inspect(row):
            nonlocal pages
            host, root, depth = row["hostname"], row["root"], row["depth"]
            finding = Finding(host, root, row["scope"])
            if config.mode == "discover":
                self.store.complete(job_id, finding)
                return
            try:
                finding.ips = await network.addresses(host)
            except (OSError, RuntimeError, TimeoutError) as error:
                finding.errors.append(str(error))
            try:
                finding.cnames = await network.cname_chain(host)
            except (OSError, RuntimeError, TimeoutError) as error:
                finding.errors.append(str(error))
            if not finding.ips:
                finding.errors.append("No current A/AAAA records")
            should_read = (
                config.related
                and row["scope"] == "in_scope"
                and depth < config.max_depth
                and pages < config.max_pages
            )
            if should_read:
                pages += 1
            response = {"headers": {}, "body": "", "tls": {}}
            if finding.ips:
                response = await network.fetch(host, body=should_read)
                if response.get("status") in {405, 501} and not should_read:
                    response = await network.fetch(host, body=True)
                if response.get("status") is None and response.get("error") != "non_public_address":
                    https_error = response.get("error", "HTTPS failed")
                    response = await network.fetch(host, body=should_read, scheme="http")
                    finding.errors.append(https_error)
                finding.status = response.get("status")
                finding.latency_ms = response.get("latency_ms", 0)
                finding.tls = response.get("tls", {})
                if response.get("error"):
                    finding.errors.append(response["error"])
            finding.asns = []
            early = detector.identify(finding.cnames, response.get("headers", {}), finding.ips)
            if config.asn and early["confidence"] not in {"high", "medium"}:
                try:
                    finding.asns = await network.asns(finding.ips)
                except Exception as error:
                    finding.errors.append(f"ASN source: {type(error).__name__}")
            identified = detector.identify(
                finding.cnames, response.get("headers", {}), finding.ips, finding.asns
            )
            for name, value in identified.items():
                setattr(finding, name, value)
            self.store.complete(job_id, finding)
            if config.related and depth < config.max_depth:
                for cname in finding.cnames:
                    add(cname, "dns_cname", host, "cname_target", depth + 1, root)
                for name in finding.tls.get("sans", []):
                    for target, pattern in certificate_names(name):
                        if not pattern:
                            add(target, "tls_san", host, "shared_certificate_name", depth + 1, root)
                if response.get("redirect"):
                    add(response["redirect"], "http_redirect", host, "redirect_target", depth + 1, root)
                if should_read and response.get("body"):
                    for target, relation in html_hosts(
                        response["body"], response.get("url", f"https://{host}/")
                    ).items():
                        add(target, "html_link", host, relation, depth + 1, root)
            self.on_event({"event": "checked", "job": job_id, "hostname": host, "provider": finding.provider})

        async def verification_worker():
            while True:
                row = self.store.claim(job_id, config.probe_related)
                if row is None:
                    if self.store.remaining(job_id, config.probe_related) == 0:
                        return
                    await asyncio.sleep(0.02)
                    continue
                try:
                    await inspect(row)
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    finding = Finding(
                        row["hostname"],
                        row["root"],
                        row["scope"],
                        errors=[f"Verification: {type(error).__name__}: {str(error)[:200]}"],
                    )
                    self.store.complete(job_id, finding)

        self.store.state(job_id, "running")
        try:
            if job["phase"] == "discovery":
                for root in config.roots:
                    add(root, "input", depth=0)
                for seed in config.seeds:
                    add(seed, "import", depth=1)
                for root in config.roots:
                    if config.ct:
                        await source(root, "Certificate Transparency", lambda r=root: ct(r))
                    if config.commoncrawl:
                        await source(root, "Common Crawl", lambda r=root: crawl(r))
                    if config.wordlist:
                        await source(root, "DNS wordlist", lambda r=root: word(r))
                self.store.state(job_id, "running", "verification")
            await asyncio.gather(*(verification_worker() for _ in range(config.workers)))
            stats = self.store.job(job_id)
            if stats["in_scope"] >= config.max_hosts or (
                config.max_related and stats["related"] >= config.max_related
            ):
                self.store.warning(
                    job_id,
                    "Configured finding limit reached; increase limits in a new job for broader discovery",
                )
            self.store.state(job_id, "completed", "done")
        except asyncio.CancelledError:
            self.store.state(job_id, "stopped" if self.stop_requested.is_set() else "paused")
        except Exception as error:
            self.store.warning(job_id, f"Job failed: {type(error).__name__}: {str(error)[:160]}")
            self.store.state(job_id, "failed")
        finally:
            self.store.release_claims(job_id)
            await network.close()


class Controller:
    """Thread-safe API/UI control; pausing cancels active I/O and requeues unfinished records."""

    def __init__(self, store, network_factory=Network):
        self.store, self.factory = store, network_factory
        self.lock = threading.RLock()
        self.thread = None
        self.loop = None
        self.task = None
        self.engine = None
        self.active_id = None

    @property
    def active(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, job_id: int, run_queue=False):
        with self.lock:
            if self.active:
                raise ValueError("Another Finder job is running")
            self.store.job(job_id)
            if self.store.job(job_id)["state"] == "completed":
                raise ValueError("Job already completed; reuse settings to create a new job")
            ready = threading.Event()
            self.active_id = job_id

            def run():
                async def runner():
                    self.loop = asyncio.get_running_loop()
                    current = job_id
                    while True:
                        self.active_id = current
                        self.engine = Engine(self.store, self.factory)
                        self.task = asyncio.create_task(self.engine.run(current))
                        await asyncio.sleep(0)
                        ready.set()
                        await self.task
                        if not run_queue or self.store.job(current)["state"] != "completed":
                            break
                        queued = sorted(j["id"] for j in self.store.jobs() if j["state"] == "queued")
                        if not queued:
                            break
                        current = queued[0]

                asyncio.run(runner())

            self.thread = threading.Thread(target=run, name="noway-finder", daemon=True)
            self.thread.start()
            ready.wait(5)

    def pause(self, stop=False):
        with self.lock:
            if not self.active or self.loop is None or self.task is None:
                raise ValueError("No active Finder job")
            if stop:
                self.engine.stop_requested.set()
            else:
                self.engine.pause_requested.set()
            self.loop.call_soon_threadsafe(self.task.cancel)

    def wait(self, timeout=None):
        if self.thread:
            self.thread.join(timeout)

    def close(self):
        if self.active:
            self.pause()
            self.wait(10)
