from typing import Any, Dict, Iterable, Set

from .models import ScanReport


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# Surfaceproof scan report", "", f"Started: {report.started_at}",
        f"Completed: {report.completed_at}", f"Requests: {report.request_count}",
        f"Bytes inspected: {report.total_bytes}", "", "## Findings", "",
    ]
    if not report.findings:
        lines.append("No candidates were identified in the bounded resources reviewed.")
    for finding in report.findings:
        lines.extend([
            f"### {finding.kind} — {finding.classification}", "",
            f"- Confidence: {finding.confidence}", f"- Fingerprint: `{finding.fingerprint}`",
            f"- Redacted: `{finding.redacted}`", f"- Source: `{finding.source_url}:{finding.line}`",
            f"- Context: {finding.context}", "",
        ])
    lines.extend(["## Coverage", "", "This is a bounded result, not a claim that the host is globally clean.", ""])
    return "\n".join(lines)


def render_sarif(report: ScanReport) -> Dict[str, Any]:
    rules = {finding.kind for finding in report.findings}
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "surfaceproof", "rules": [{"id": rule, "name": rule} for rule in sorted(rules)]}},
            "results": [{
                "ruleId": finding.kind,
                "level": "warning" if finding.confidence == "high" else "note",
                "message": {"text": f"{finding.classification}: {finding.redacted} (fp {finding.fingerprint})"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.source_url}, "region": {"startLine": finding.line}}}],
                "fingerprints": {"surfaceproof/v1": finding.fingerprint},
            } for finding in report.findings],
        }],
    }


def _fingerprints(report: Dict[str, Any]) -> Set[str]:
    return {item["fingerprint"] for item in report.get("findings", [])}


def diff_reports(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    before, after = _fingerprints(old), _fingerprints(new)
    return {
        "new": sorted(after - before),
        "resolved": sorted(before - after),
        "persistent": sorted(before & after),
        "old_completed_at": old.get("completed_at"),
        "new_completed_at": new.get("completed_at"),
    }
