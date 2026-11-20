"""Versioned, JSON-serializable public contracts shared by CLI, UI and Edge adapters."""

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Config:
    roots: tuple[str, ...]
    mode: str = "verify"
    ct: bool = True
    commoncrawl: bool = False
    source_pages: int = 3
    wordlist: bool = False
    related: bool = True
    asn: bool = True
    workers: int = 32
    rate: float = 30.0
    timeout: float = 8.0
    retries: int = 1
    max_hosts: int = 10000
    max_related: int = 2000
    max_depth: int = 2
    max_pages: int = 20
    custom_words: tuple[str, ...] = ()
    seeds: tuple[str, ...] = ()
    verify_tls: bool = True
    allow_private: bool = False
    probe_related: bool = False
    dns_servers: tuple[str, ...] = ()

    def __post_init__(self):
        for server in self.dns_servers:
            try:
                ipaddress.ip_address(server)
            except ValueError as error:
                raise ValueError("DNS resolvers must be numeric IP addresses") from error
        if not self.roots or len(self.roots) > 1000:
            raise ValueError("Provide 1–1000 root domains")
        if self.mode not in {"discover", "verify"}:
            raise ValueError("mode must be discover or verify")
        if self.mode == "discover" and self.wordlist:
            raise ValueError("DNS wordlist queries require verification mode")
        for name, low, high in (
            ("workers", 1, 128),
            ("max_hosts", 1, 100000),
            ("max_related", 0, 100000),
            ("max_depth", 0, 5),
            ("max_pages", 0, 200),
            ("source_pages", 1, 20),
            ("retries", 0, 3),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{name} must be an integer from {low} to {high}")
        if isinstance(self.rate, bool) or not 0 < float(self.rate) <= 500:
            raise ValueError("rate must be greater than 0 and at most 500 requests/s")
        if isinstance(self.timeout, bool) or not 0.1 <= float(self.timeout) <= 60:
            raise ValueError("timeout must be between 0.1 and 60 seconds")
        if len(self.seeds) > 100000 or len(self.custom_words) > 100000:
            raise ValueError("Import contains more than 100,000 entries")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict):
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError("Unknown settings: " + ", ".join(sorted(unknown)))
        data = dict(data)
        for key in ("roots", "seeds", "custom_words", "dns_servers"):
            if key in data:
                if not isinstance(data[key], (list, tuple)) or any(not isinstance(v, str) for v in data[key]):
                    raise ValueError(f"{key} must be an array of strings")
                data[key] = tuple(data[key])
        for key in (
            "ct",
            "commoncrawl",
            "wordlist",
            "related",
            "asn",
            "verify_tls",
            "allow_private",
            "probe_related",
        ):
            if key in data and not isinstance(data[key], bool):
                raise ValueError(f"{key} must be true or false")
        return cls(**data)


@dataclass
class Finding:
    hostname: str
    root: str
    scope: str = "in_scope"
    provider: str = "Unknown"
    confidence: str = "unknown"
    hosting: str = ""
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    status: int | None = None
    latency_ms: float = 0
    tls: dict = field(default_factory=dict)
    evidence: list[dict] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    wildcard: bool = False
    checked_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Filter:
    query: str = ""
    provider: str = ""
    scope: str = ""
    confidence: str = ""
    alive_only: bool = False
    cdn_only: bool = False
    include_wildcard: bool = False
    status: int | None = None
    family: int = 0

    def __post_init__(self):
        if self.scope not in {"", "in_scope", "related"}:
            raise ValueError("Invalid scope filter")
        if self.confidence not in {"", "high", "medium", "low", "unknown"}:
            raise ValueError("Invalid confidence filter")
        if self.family not in {0, 4, 6}:
            raise ValueError("IP family must be 0, 4 or 6")
        if self.status is not None and not 100 <= int(self.status) <= 599:
            raise ValueError("Invalid HTTP status")
