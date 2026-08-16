import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import urlsplit


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Scope:
    allowed_hosts: Tuple[str, ...]
    max_requests: int = 50
    max_total_bytes: int = 10_000_000
    max_asset_bytes: int = 2_000_000
    delay_seconds: float = 0.25
    user_agent: str = "surfaceproof/0.1 (+https://github.com/pzzzy/surfaceproof)"
    allow_http: bool = False
    allowed_ports: Tuple[int, ...] = ()

    @classmethod
    def from_file(cls, path: Path) -> "Scope":
        try:
            raw: Dict[str, Any] = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ScopeError(f"invalid scope file: {exc}") from exc
        known = {
            "allowed_hosts", "max_requests", "max_total_bytes", "max_asset_bytes",
            "delay_seconds", "user_agent", "allow_http", "allowed_ports",
        }
        unknown = set(raw) - known
        if unknown:
            raise ScopeError(f"unknown scope fields: {', '.join(sorted(unknown))}")
        hosts = raw.get("allowed_hosts")
        if not isinstance(hosts, list) or not hosts:
            raise ScopeError("allowed_hosts must be a non-empty list")
        normalized = []
        for host in hosts:
            if not isinstance(host, str) or not host.strip():
                raise ScopeError("allowed_hosts entries must be hostnames")
            host = host.lower().rstrip(".")
            if "*" in host:
                raise ScopeError("wildcards are not supported; list exact allowed hosts")
            if "://" in host or "/" in host or ":" in host:
                raise ScopeError("allowed_hosts must contain exact hostnames only")
            normalized.append(host)
        kwargs = dict(raw)
        kwargs["allowed_hosts"] = tuple(dict.fromkeys(normalized))
        kwargs["allowed_ports"] = tuple(raw.get("allowed_ports", ()))
        scope = cls(**kwargs)
        scope._validate()
        return scope

    def _validate(self) -> None:
        for name in ("max_requests", "max_total_bytes", "max_asset_bytes"):
            if not isinstance(getattr(self, name), int) or getattr(self, name) <= 0:
                raise ScopeError(f"{name} must be a positive integer")
        if not isinstance(self.delay_seconds, (int, float)) or self.delay_seconds < 0:
            raise ScopeError("delay_seconds must be non-negative")
        if self.max_asset_bytes > self.max_total_bytes:
            raise ScopeError("max_asset_bytes cannot exceed max_total_bytes")
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in self.allowed_ports):
            raise ScopeError("allowed_ports must contain valid integer ports")

    def allows_url(self, url: str) -> bool:
        parsed = urlsplit(url)
        schemes = {"https"} | ({"http"} if self.allow_http else set())
        if parsed.scheme not in schemes or parsed.hostname not in self.allowed_hosts:
            return False
        default_port = 443 if parsed.scheme == "https" else 80
        try:
            port = parsed.port or default_port
        except ValueError:
            return False
        return port == default_port or port in self.allowed_ports

    def public_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["allowed_hosts"] = list(self.allowed_hosts)
        data["allowed_ports"] = list(self.allowed_ports)
        return data
