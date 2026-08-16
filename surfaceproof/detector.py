import hashlib
import re
from typing import Dict, List, Pattern, Tuple

from .models import Finding


PatternSpec = Tuple[str, Pattern[str], str]
PATTERNS: List[PatternSpec] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}"), "credential_candidate"),
    ("github_classic_pat", re.compile(r"ghp_[A-Za-z0-9]{36}"), "credential_candidate"),
    ("stripe_live_secret", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}"), "credential_candidate"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"), "credential_candidate"),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "credential_candidate"),
    ("public_client_id", re.compile(r"(?i)clientId\s*[:=]\s*[\"']([A-Za-z0-9_-]{8,})[\"']"), "public_identifier"),
    ("sanity_project_id", re.compile(r"(?i)projectId\s*[:=]\s*[\"']([a-z0-9]{8})[\"']"), "public_identifier"),
]
FIXTURE_WORDS = re.compile(r"(?i)example|sample|placeholder|fixture|dummy|documentation|replace[-_ ]?me")


def _redact(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "…" + value[-2:]
    return value[:4] + "…" + value[-4:]


def detect(text: str, source_url: str) -> List[Finding]:
    findings: List[Finding] = []
    seen: Dict[Tuple[str, str], bool] = {}
    for kind, pattern, default_classification in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            fingerprint = hashlib.sha256(value.encode()).hexdigest()[:12]
            key = (kind, fingerprint)
            if key in seen:
                continue
            seen[key] = True
            start = max(0, match.start() - 100)
            end = min(len(text), match.end() + 100)
            context_text = text[start:end]
            line = text.count("\n", 0, match.start()) + 1
            classification = default_classification
            confidence = "high" if classification == "credential_candidate" else "informational"
            if classification == "credential_candidate" and FIXTURE_WORDS.search(context_text):
                classification = "likely_fixture"
                confidence = "low"
            context = "fixture-like context" if classification == "likely_fixture" else "assignment"
            if classification == "public_identifier":
                context = "browser-intended identifier"
            findings.append(Finding(kind, classification, confidence, fingerprint, _redact(value), source_url, line, context))
    return findings
