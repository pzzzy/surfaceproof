from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class Finding:
    kind: str
    classification: str
    confidence: str
    fingerprint: str
    redacted: str
    source_url: str
    line: int
    context: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Resource:
    requested_url: str
    final_url: str
    status: int
    content_type: str
    byte_count: int
    sha256: str
    redirect_blocked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    started_at: str
    completed_at: str
    scope: Dict[str, Any]
    seeds: List[str]
    resources: List[Resource]
    findings: List[Finding]
    skipped_urls: List[str]
    request_count: int
    total_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "scope": self.scope,
            "seeds": self.seeds,
            "resources": [item.to_dict() for item in self.resources],
            "findings": [item.to_dict() for item in self.findings],
            "skipped_urls": self.skipped_urls,
            "request_count": self.request_count,
            "total_bytes": self.total_bytes,
        }
