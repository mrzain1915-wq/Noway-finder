"""Explicit refresh of public CDN IP feeds; only validated official sources are accepted."""

import ipaddress
import json

from .models import Config
from .network import Network


async def update_prefixes(store) -> dict:
    net = Network(Config(("example.com",), ct=False), store)
    try:
        values = []
        for suffix in ("ips-v4/", "ips-v6/"):
            values.extend(
                (
                    await net.public_api(
                        "https://www.cloudflare.com/" + suffix, cache_ttl=86400, max_bytes=100000
                    )
                ).splitlines()
            )
        fastly = json.loads(
            await net.public_api("https://api.fastly.com/public-ip-list", cache_ttl=86400, max_bytes=100000)
        )
        prefixes = {"Cloudflare": values, "Fastly": fastly["addresses"] + fastly["ipv6_addresses"]}
        clean = {}
        for provider, records in prefixes.items():
            networks = [str(ipaddress.ip_network(record.strip())) for record in records if record.strip()]
            if not networks or len(networks) > 5000:
                raise ValueError("Unexpected published prefix count")
            if any(ipaddress.ip_network(n).prefixlen < 8 for n in networks):
                raise ValueError("Unexpectedly broad published network")
            clean[provider] = sorted(set(networks))
        store.cache_put("published_prefixes", clean, 7 * 86400)
        return {provider: len(prefixes) for provider, prefixes in clean.items()}
    finally:
        await net.close()
