import json
from pathlib import Path

import pytest

from surfaceproof.scope import Scope, ScopeError


def test_scope_requires_nonempty_explicit_allowed_hosts(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"allowed_hosts": []}))
    with pytest.raises(ScopeError, match="allowed_hosts"):
        Scope.from_file(path)


def test_scope_normalizes_hosts_and_rejects_wildcards(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"allowed_hosts": ["Example.COM.", "*.example.com"]}))
    with pytest.raises(ScopeError, match="wildcards"):
        Scope.from_file(path)


def test_scope_applies_safe_defaults_and_url_policy(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"allowed_hosts": ["Example.COM."]}))
    scope = Scope.from_file(path)
    assert scope.allowed_hosts == ("example.com",)
    assert scope.max_requests == 50
    assert scope.max_total_bytes == 10_000_000
    assert scope.max_asset_bytes == 2_000_000
    assert scope.delay_seconds == 0.25
    assert scope.allows_url("https://example.com/app.js")
    assert not scope.allows_url("http://example.com/app.js")
    assert not scope.allows_url("https://cdn.example.com/app.js")
    assert not scope.allows_url("https://example.com:444/app.js")


def test_scope_rejects_unknown_fields_and_unsafe_budget_values(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"allowed_hosts": ["example.com"], "surprise": True}))
    with pytest.raises(ScopeError, match="unknown"):
        Scope.from_file(path)
    path.write_text(json.dumps({"allowed_hosts": ["example.com"], "max_requests": 0}))
    with pytest.raises(ScopeError, match="max_requests"):
        Scope.from_file(path)
