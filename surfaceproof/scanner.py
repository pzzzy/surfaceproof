import hashlib
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .detector import detect
from .models import Finding, Resource, ScanReport
from .scope import Scope


class ScanError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.assets.append(values["src"])
        if tag == "link" and values.get("href") and "stylesheet" in values.get("rel", "").lower():
            self.assets.append(values["href"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Scanner:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self.opener = build_opener(_NoRedirect())

    def scan(self, seeds: List[str]) -> ScanReport:
        if not seeds:
            raise ScanError("at least one seed URL is required")
        for seed in seeds:
            if not self.scope.allows_url(seed):
                raise ScanError(f"seed outside explicit scope: {seed}")
        started = _now()
        queue = list(dict.fromkeys(seeds))
        seen: Set[str] = set()
        resources: List[Resource] = []
        findings: List[Finding] = []
        skipped: List[str] = []
        total_bytes = 0
        while queue:
            url = queue.pop(0)
            if url in seen:
                continue
            if not self.scope.allows_url(url):
                skipped.append(url)
                continue
            if len(resources) >= self.scope.max_requests:
                raise ScanError("request budget exceeded")
            seen.add(url)
            if resources and self.scope.delay_seconds:
                time.sleep(self.scope.delay_seconds)
            resource, body, location = self._fetch(url)
            if resource.byte_count > self.scope.max_asset_bytes:
                raise ScanError(f"asset byte budget exceeded: {url}")
            total_bytes += resource.byte_count
            if total_bytes > self.scope.max_total_bytes:
                raise ScanError("total byte budget exceeded")
            resources.append(resource)
            if location:
                target = urljoin(resource.final_url, location)
                if self.scope.allows_url(target):
                    queue.append(target)
                else:
                    skipped.append(target)
                continue
            text = body.decode("utf-8", "replace")
            findings.extend(detect(text, resource.final_url))
            content_type = resource.content_type.lower()
            if "text/html" in content_type:
                parser = _AssetParser()
                parser.feed(text)
                for raw in parser.assets:
                    target = urljoin(resource.final_url, raw)
                    (queue if self.scope.allows_url(target) else skipped).append(target)
            if "javascript" in content_type or resource.final_url.endswith((".js", ".mjs")):
                for target in self._source_maps(text, resource.final_url):
                    (queue if self.scope.allows_url(target) else skipped).append(target)
        return ScanReport(started, _now(), self.scope.public_dict(), seeds, resources, findings, sorted(set(skipped)), len(resources), total_bytes)

    def _fetch(self, url: str) -> Tuple[Resource, bytes, Optional[str]]:
        request = Request(url, headers={"User-Agent": self.scope.user_agent, "Accept": "text/html,application/javascript,text/css,application/json,*/*;q=0.1"})
        try:
            response = self.opener.open(request, timeout=20)
            body = response.read(self.scope.max_asset_bytes + 1)
            status = response.status
            final_url = response.geturl()
            headers = response.headers
        except HTTPError as exc:
            status = exc.code
            final_url = exc.geturl()
            headers = exc.headers
            body = exc.read(self.scope.max_asset_bytes + 1) if status not in (301, 302, 303, 307, 308) else b""
        except URLError as exc:
            raise ScanError(f"request failed for {url}: {exc.reason}") from exc
        location = headers.get("Location") if status in (301, 302, 303, 307, 308) else None
        redirect_blocked = bool(location and not self.scope.allows_url(urljoin(final_url, location)))
        resource = Resource(url, final_url, status, headers.get_content_type(), len(body), hashlib.sha256(body).hexdigest(), redirect_blocked)
        return resource, body, location

    @staticmethod
    def _source_maps(text: str, base_url: str) -> List[str]:
        import re
        return [urljoin(base_url, match.strip("\"'")) for match in re.findall(r"(?m)[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)", text)]
