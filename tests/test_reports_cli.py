import json
from pathlib import Path

from surfaceproof.cli import main
from surfaceproof.models import Finding, Resource, ScanReport
from surfaceproof.reporting import diff_reports, render_markdown, render_sarif


def sample_report(fingerprint: str = "abc123abc123") -> ScanReport:
    return ScanReport(
        started_at="2026-08-16T00:00:00Z",
        completed_at="2026-08-16T00:00:01Z",
        scope={"allowed_hosts": ["example.com"]},
        seeds=["https://example.com/"],
        resources=[Resource("https://example.com/", "https://example.com/", 200, "text/html", 12, "a" * 64)],
        findings=[Finding("aws_access_key_id", "credential_candidate", "high", fingerprint, "AKIA…AAAA", "https://example.com/", 1, "assignment")],
        skipped_urls=[],
        request_count=1,
        total_bytes=12,
    )


def test_renderers_never_include_unredacted_material() -> None:
    report = sample_report()
    markdown = render_markdown(report)
    sarif = json.dumps(render_sarif(report))
    assert "AKIA…AAAA" in markdown
    assert "abc123abc123" in sarif
    assert "credential_candidate" in markdown


def test_diff_reports_tracks_new_resolved_and_persistent() -> None:
    old = sample_report("oldoldoldold")
    new = sample_report("newnewnewnew")
    result = diff_reports(old.to_dict(), new.to_dict())
    assert result["new"] == ["newnewnewnew"]
    assert result["resolved"] == ["oldoldoldold"]
    assert result["persistent"] == []


def test_cli_diff_writes_machine_readable_output(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    out = tmp_path / "diff.json"
    old.write_text(json.dumps(sample_report("oldoldoldold").to_dict()))
    new.write_text(json.dumps(sample_report("newnewnewnew").to_dict()))
    assert main(["diff", str(old), str(new), "--output", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["new"] == ["newnewnewnew"]
