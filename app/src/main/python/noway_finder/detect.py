"""Evidence-backed identification; generic AWS/Azure hosting is separate from CDN proof."""

import ipaddress
import json
from importlib.resources import files
from pathlib import Path


class Detector:
    def __init__(self, rules_path: str | None = None, prefixes: dict | None = None):
        text = (
            Path(rules_path).read_text(encoding="utf-8")
            if rules_path
            else files("noway_finder").joinpath("data/providers.json").read_text(encoding="utf-8")
        )
        data = json.loads(text)
        if data.get("schema") != 1 or not isinstance(data.get("providers"), list):
            raise ValueError("Invalid provider rules schema")
        self.rules = data["providers"]
        names = set()
        for rule in self.rules:
            if not isinstance(rule.get("name"), str) or rule["name"] in names:
                raise ValueError("Invalid or duplicate provider name")
            names.add(rule["name"])
            for key in ("cnames", "headers", "servers", "asns"):
                if not isinstance(rule.get(key), list) or any(not isinstance(v, str) for v in rule[key]):
                    raise ValueError("Invalid provider rule values")
        self.prefixes = {
            name: [ipaddress.ip_network(value) for value in values]
            for name, values in (prefixes or {}).items()
        }

    def identify(self, cnames=(), headers=None, ips=(), asns=()) -> dict:
        headers = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
        scores: dict[str, tuple[int, list[dict]]] = {}
        for rule in self.rules:
            evidence = []
            for name in cnames:
                if any(
                    name.lower() == suffix or name.lower().endswith("." + suffix) for suffix in rule["cnames"]
                ):
                    evidence.append({"type": "cname", "value": name})
            for key in rule["headers"]:
                # Generic X-ID on its own is not a unique CDN identifier.
                if key in headers and key not in {"x-id", "x-id-fe"}:
                    evidence.append({"type": "header", "value": key})
            if any(server in headers.get("server", "") for server in rule["servers"]):
                evidence.append({"type": "server", "value": headers["server"][:200]})
            if rule["name"] == "Fastly" and "x-served-by" in headers and "x-cache" in headers:
                # This combination is supporting evidence, shared by some other caches.
                evidence.append({"type": "cache_headers", "value": "x-served-by + x-cache"})
            if any(str(asn).removeprefix("AS") in rule["asns"] for asn in asns):
                evidence.append({"type": "asn", "value": ",".join(asns)})
            for ip in ips:
                try:
                    address = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if any(
                    address.version == net.version and address in net
                    for net in self.prefixes.get(rule["name"], [])
                ):
                    evidence.append({"type": "published_prefix", "value": ip})
            weights = {
                "cname": 85,
                "header": 80,
                "server": 65,
                "asn": 45,
                "published_prefix": 85,
                "cache_headers": 25,
            }
            if evidence:
                kinds = {e["type"] for e in evidence}
                score = min(99, max(weights[k] for k in kinds) + 5 * (len(kinds) - 1))
                scores[rule["name"]] = score, evidence
        hosting = ""
        if any(str(a).removeprefix("AS") in {"16509", "14618"} for a in asns):
            hosting = "AWS"
        elif any(str(a).removeprefix("AS") == "8075" for a in asns):
            hosting = "Microsoft Azure"
        if not scores:
            return {"provider": "Unknown", "confidence": "unknown", "evidence": [], "hosting": hosting}
        ordered = sorted(scores.items(), key=lambda item: (-item[1][0], item[0]))
        name, (score, evidence) = ordered[0]
        if score < 40:
            return {"provider": "Unknown", "confidence": "unknown", "evidence": evidence, "hosting": hosting}
        if len(ordered) > 1 and ordered[1][1][0] >= 65:
            evidence.append({"type": "conflict", "value": ordered[1][0]})
            score = min(score, 60)
        return {
            "provider": name,
            "confidence": "high" if score >= 80 else "medium" if score >= 60 else "low",
            "evidence": evidence,
            "hosting": hosting,
        }
