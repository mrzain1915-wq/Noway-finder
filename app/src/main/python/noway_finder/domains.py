"""Strict canonical hostnames, public-suffix boundaries, scoped HTML discovery and imports."""

import csv
import io
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import idna
import tldextract

_suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def hostname(value: str) -> str:
    value = value.strip().lstrip("\ufeff")
    if not value or len(value) > 4096 or any(ord(c) < 32 or c.isspace() for c in value):
        raise ValueError("Empty or invalid hostname")
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP/HTTPS URLs and DNS hostnames are supported")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("Credentials and empty hosts are not supported")
    host = parsed.hostname.rstrip(".")
    if host.startswith("*."):
        raise ValueError("Wildcard is a DNS pattern, not a concrete hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain, not an IP range or address")
    try:
        host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as error:
        raise ValueError("Invalid internationalized hostname") from error
    if len(host) > 253 or "." not in host:
        raise ValueError("A fully qualified domain name is required")
    suffix = _suffixes(host)
    if suffix.suffix and not suffix.domain:
        raise ValueError("A public suffix alone is not a target domain")
    return host


def try_host(value: str) -> str | None:
    try:
        return hostname(value)
    except (ValueError, TypeError, UnicodeError):
        return None


def registered_domain(host: str) -> str:
    parts = _suffixes(host)
    return parts.top_domain_under_public_suffix or ".".join(host.split(".")[-2:])


def matching_root(host: str, roots: tuple[str, ...]) -> str | None:
    matches = [root for root in roots if host == root or host.endswith("." + root)]
    return max(matches, key=len) if matches else None


def normalize_roots(values) -> tuple[str, ...]:
    return tuple(dict.fromkeys(hostname(v) for v in values))


def certificate_names(value: str) -> list[tuple[str, bool]]:
    result = []
    for name in value.splitlines():
        wildcard = name.strip().startswith("*.")
        host = try_host(name.strip()[2:] if wildcard else name)
        if host:
            result.append((host, wildcard))
    return result


def import_hosts(text: str) -> tuple[list[str], list[str]]:
    """Parse TXT or quoted CSV; domain/hostname/target/url columns take precedence."""
    if len(text.encode("utf-8")) > 20 * 1024 * 1024:
        raise ValueError("Import exceeds 20 MiB")
    text = text.lstrip("\ufeff")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return [], []
    header = [s.strip().lower() for s in rows[0]]
    column = next(
        (header.index(k) for k in ("hostname", "domain", "target", "url", "subdomain") if k in header), None
    )
    values = (
        [(r[column] if column < len(r) else "") for r in rows[1:]]
        if column is not None
        else [cell for row in rows for cell in row]
    )
    result, errors, seen = [], [], set()
    for value in values:
        value = value.strip()
        if not value or value.startswith("#"):
            continue
        host = try_host(value)
        if host is None:
            errors.append(value[:100])
        elif host not in seen:
            seen.add(host)
            result.append(host)
        if len(result) > 100000:
            raise ValueError("Import exceeds 100,000 unique hosts")
    return result, errors


class LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.hosts: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "base" and attributes.get("href"):
            self.base = urljoin(self.base, attributes["href"])
        for key in ("href", "src", "action", "poster", "data-src"):
            if attributes.get(key):
                self.add(attributes[key], f"html:{tag}:{key}")
        if attributes.get("srcset"):
            for item in attributes["srcset"].split(","):
                bits = item.strip().split()
                if bits:
                    self.add(bits[0], "html:srcset")

    def add(self, value: str, relation: str):
        if len(self.hosts) >= 10000:
            return
        target = urljoin(self.base, value)
        if urlsplit(target).scheme not in {"http", "https"}:
            return
        host = try_host(target)
        if host:
            self.hosts.setdefault(host, relation)


def html_hosts(body: str, base_url: str) -> dict[str, str]:
    parser = LinkExtractor(base_url)
    parser.feed(body[:1_048_576])
    return parser.hosts


def valid_word(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,249}[a-z0-9])?", value))
