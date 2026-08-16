import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from surfaceproof.scanner import ScanError, Scanner
from surfaceproof.scope import Scope


class FixtureHandler(BaseHTTPRequestHandler):
    requests_seen = []

    def do_GET(self):  # noqa: N802
        type(self).requests_seen.append(self.path)
        routes = {
            "/": (200, "text/html", b'<script src="/app.js"></script><script src="https://outside.invalid/x.js"></script><link rel="stylesheet" href="/style.css">'),
            "/app.js": (200, "application/javascript", ('const key="' + "AKIA" + "A" * 16 + '"; //# sourceMappingURL=app.js.map').encode()),
            "/app.js.map": (200, "application/json", b'{"sources":["src/app.js"],"x":"safe"}'),
            "/style.css": (200, "text/css", b"body { color: #111; }"),
            "/redirect": (302, "text/plain", b""),
            "/large": (200, "text/plain", b"x" * 4096),
        }
        status, content_type, body = routes.get(self.path, (404, "text/plain", b"missing"))
        self.send_response(status)
        if self.path == "/redirect":
            self.send_header("Location", "https://outside.invalid/")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture
def fixture_server():
    FixtureHandler.requests_seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


def make_scope(host: str, port: int = 0, **overrides) -> Scope:
    values = dict(
        allowed_hosts=(host,),
        allow_http=True,
        allowed_ports=(port,) if port else (),
        max_requests=10,
        max_total_bytes=20_000,
        max_asset_bytes=2_000,
        delay_seconds=0,
        user_agent="surfaceproof-test",
    )
    values.update(overrides)
    return Scope(**values)


def test_scanner_fetches_only_directly_referenced_in_scope_assets_and_maps(fixture_server: str) -> None:
    scope = make_scope("127.0.0.1", urlsplit(fixture_server).port)
    report = Scanner(scope).scan([fixture_server + "/"])
    paths = {item.requested_url.split(fixture_server)[-1] for item in report.resources}
    assert paths == {"/", "/app.js", "/app.js.map", "/style.css"}
    assert "https://outside.invalid/x.js" in report.skipped_urls
    assert report.request_count == 4
    assert any(f.kind == "aws_access_key_id" for f in report.findings)
    serialized = json.dumps(report.to_dict())
    raw_candidate = "AKIA" + "A" * 16
    assert raw_candidate not in serialized


def test_scanner_blocks_out_of_scope_redirect_without_following_it(fixture_server: str) -> None:
    report = Scanner(make_scope("127.0.0.1", urlsplit(fixture_server).port)).scan([fixture_server + "/redirect"])
    assert report.resources[0].status == 302
    assert report.resources[0].redirect_blocked
    assert report.request_count == 1


def test_scanner_enforces_per_asset_and_total_budgets(fixture_server: str) -> None:
    port = urlsplit(fixture_server).port
    with pytest.raises(ScanError, match="asset byte budget"):
        Scanner(make_scope("127.0.0.1", port, max_asset_bytes=100)).scan([fixture_server + "/large"])
    with pytest.raises(ScanError, match="total byte budget"):
        Scanner(make_scope("127.0.0.1", port, max_total_bytes=100, max_asset_bytes=10_000)).scan([fixture_server + "/large"])


def test_scanner_refuses_seed_outside_scope() -> None:
    with pytest.raises(ScanError, match="outside explicit scope"):
        Scanner(make_scope("example.com")).scan(["https://other.example/"])
