"""Bounded async DNS/HTTP, current resolver APIs, TLS verification and API retry handling."""

import asyncio
import ipaddress
import json
import ssl
import time
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin

import dns.asyncresolver
import dns.exception
import httpx

from .domains import try_host


class Pacer:
    def __init__(self, rate: float):
        self.interval = 1 / rate
        self.lock = asyncio.Lock()
        self.next = 0.0

    async def wait(self):
        async with self.lock:
            now = asyncio.get_running_loop().time()
            slot = max(now, self.next)
            self.next = slot + self.interval
        await asyncio.sleep(max(0, slot - now))


class Network:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.pacer = Pacer(config.rate)
        self.api_pacer = Pacer(1)
        self.resolver = dns.asyncresolver.Resolver()
        if config.dns_servers:
            self.resolver.nameservers = list(config.dns_servers)
        self.resolver.timeout = config.timeout
        self.resolver.lifetime = config.timeout
        self.client = httpx.AsyncClient(
            verify=config.verify_tls,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(config.timeout),
            limits=httpx.Limits(max_connections=config.workers * 2, max_keepalive_connections=config.workers),
            headers={
                "User-Agent": "NOWAY-Finder/1.0 (+domain/CDN diagnostics)",
                "Accept-Encoding": "identity",
            },
        )
        self.api = httpx.AsyncClient(
            verify=True,
            trust_env=False,
            timeout=30,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
        )
        self.lookup_locks: dict[str, asyncio.Lock] = {}
        self.asn_lock = asyncio.Lock()
        self.asn_prefixes = self.store.cache_get("asn_prefixes") or []

    async def close(self):
        await self.client.aclose()
        await self.api.aclose()

    async def resolve(self, host: str, kind: str) -> list[str]:
        key = f"dns:{','.join(self.config.dns_servers)}:{host}:{kind}"
        if (cached := self.store.cache_get(key)) is not None:
            return cached
        await self.pacer.wait()
        try:
            result = await self.resolver.resolve(host, kind, search=False, lifetime=self.config.timeout)
            values = [str(r).rstrip(".").lower() for r in result]
            ttl = max(10, min(result.rrset.ttl, 3600))
        except dns.resolver.NXDOMAIN:
            values, ttl = [], 60
        except dns.resolver.NoAnswer:
            values, ttl = [], 60
        except (dns.exception.DNSException, OSError) as error:
            # Transient failures are not cached as authoritative absence.
            raise RuntimeError(f"DNS {kind}: {type(error).__name__}") from error
        self.store.cache_put(key, values, ttl)
        return values

    async def cname_chain(self, host: str) -> list[str]:
        chain, seen = [], {host}
        for _ in range(12):
            records = await self.resolve(host, "CNAME")
            if not records:
                break
            target = try_host(records[0])
            if not target or target in seen:
                break
            chain.append(target)
            seen.add(target)
            host = target
        return chain

    async def addresses(self, host: str) -> list[str]:
        values = await asyncio.gather(
            self.resolve(host, "A"), self.resolve(host, "AAAA"), return_exceptions=True
        )
        good = [ip for result in values if isinstance(result, list) for ip in result]
        if not good and all(isinstance(result, Exception) for result in values):
            raise RuntimeError("DNS A and AAAA queries failed")
        return sorted(set(good))

    @staticmethod
    def public(ips: list[str]) -> bool:
        return bool(ips) and all(ipaddress.ip_address(ip).is_global for ip in ips)

    async def fetch(self, host: str, body: bool = True, scheme: str = "https") -> dict:
        """No cookies/auth forwarded; redirect destinations are recorded, never followed silently."""
        ips = await self.addresses(host)
        if not ips:
            return {"error": "unresolved", "headers": {}, "body": "", "status": None, "url": ""}
        if not self.config.allow_private and not self.public(ips):
            return {"error": "non_public_address", "headers": {}, "body": "", "status": None, "url": ""}
        # Connect to the validated numeric IP to prevent a second DNS lookup/rebinding.
        last = "network_error"
        attempts = max(self.config.retries + 1, min(len(ips), 2))
        for attempt in range(attempts):
            ip = ips[attempt % len(ips)]
            address = f"[{ip}]" if ":" in ip else ip
            url = f"{scheme}://{address}/"
            await self.pacer.wait()
            started = time.monotonic()
            try:
                async with asyncio.timeout(self.config.timeout * 2):
                    async with self.client.stream(
                        "GET" if body else "HEAD",
                        url,
                        headers={"Host": host},
                        extensions={"sni_hostname": host},
                    ) as response:
                        tls = {}
                        stream = response.extensions.get("network_stream")
                        obj = stream.get_extra_info("ssl_object") if stream else None
                        if obj:
                            cert = obj.getpeercert()
                            tls = {
                                "verified": self.config.verify_tls,
                                "issuer": str(cert.get("issuer", "")),
                                "expires": cert.get("notAfter", ""),
                                "protocol": obj.version(),
                                "sans": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:1000],
                            }
                        chunks, size = [], 0
                        content_type = response.headers.get("content-type", "")
                        if body and (
                            not content_type or "html" in content_type or "text/plain" in content_type
                        ):
                            async for chunk in response.aiter_bytes():
                                if size + len(chunk) > 1_048_576:
                                    chunks.append(chunk[: 1_048_576 - size])
                                    break
                                chunks.append(chunk)
                                size += len(chunk)
                        headers = {
                            k.lower(): v[:2000]
                            for k, v in response.headers.items()
                            if k.lower()
                            not in {"set-cookie", "authorization", "cookie", "proxy-authenticate"}
                        }
                        return {
                            "status": response.status_code,
                            "headers": headers,
                            "tls": tls,
                            "body": b"".join(chunks).decode("utf-8", errors="replace"),
                            "url": f"{scheme}://{host}/",
                            "error": "",
                            "redirect": urljoin(f"{scheme}://{host}/", response.headers.get("location", ""))
                            if 300 <= response.status_code < 400 and response.headers.get("location")
                            else "",
                            "latency_ms": round((time.monotonic() - started) * 1000, 2),
                        }
            except (httpx.HTTPError, OSError, TimeoutError, ssl.SSLError) as error:
                last = f"{scheme}: {type(error).__name__}"
                if attempt + 1 < attempts:
                    await asyncio.sleep(min(0.5 * 2**attempt, 2))
        return {"error": last, "headers": {}, "body": "", "status": None, "url": f"{scheme}://{host}/"}

    async def public_api(self, url: str, params=None, cache_ttl=3600, max_bytes=20 * 1024 * 1024):
        key = "api:" + url + ":" + json.dumps(params, sort_keys=True)
        if (cached := self.store.cache_get(key)) is not None:
            return cached
        async with self.lookup_locks.setdefault(key, asyncio.Lock()):
            if (cached := self.store.cache_get(key)) is not None:
                return cached
            for attempt in range(self.config.retries + 1):
                await self.api_pacer.wait()
                async with asyncio.timeout(45), self.api.stream("GET", url, params=params) as response:
                    if response.status_code in {429, 502, 503, 504} and attempt < self.config.retries:
                        value = response.headers.get("retry-after", "2")
                        try:
                            wait = float(value)
                        except ValueError:
                            try:
                                wait = parsedate_to_datetime(value).timestamp() - time.time()
                            except (ValueError, TypeError, OverflowError):
                                wait = 2
                        await asyncio.sleep(max(0, min(wait, 10)))
                        continue
                    response.raise_for_status()
                    chunks, size = [], 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValueError("Public source response exceeds size limit")
                        chunks.append(chunk)
                    text = b"".join(chunks).decode("utf-8")
                    self.store.cache_put(key, text, cache_ttl)
                    return text
            raise RuntimeError("Source request failed after retries")

    async def asns(self, ips: list[str]) -> list[str]:
        values = set()
        for ip in ips[:2]:
            address = ipaddress.ip_address(ip)
            if not address.is_global:
                continue
            async with self.asn_lock:
                cached = next(
                    (
                        entry
                        for entry in self.asn_prefixes
                        if address.version == ipaddress.ip_network(entry["prefix"]).version
                        and address in ipaddress.ip_network(entry["prefix"])
                    ),
                    None,
                )
                if cached:
                    values.update(cached["asns"])
                    continue
                data = json.loads(
                    await self.public_api(
                        "https://stat.ripe.net/data/network-info/data.json", {"resource": ip}, cache_ttl=86400
                    )
                )
                payload = data.get("data", {})
                asns = [str(v) for v in payload.get("asns", []) if str(v).isdigit()]
                values.update(asns)
                if payload.get("prefix") and asns:
                    prefix = ipaddress.ip_network(payload["prefix"])
                    if prefix.version == address.version and address in prefix and prefix.prefixlen > 0:
                        self.asn_prefixes.append({"prefix": str(prefix), "asns": asns})
                        self.asn_prefixes = self.asn_prefixes[-2000:]
                        self.store.cache_put("asn_prefixes", self.asn_prefixes, 86400)
        return sorted(values)
