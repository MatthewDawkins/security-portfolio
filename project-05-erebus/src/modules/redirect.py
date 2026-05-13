from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.models import Finding
from src.modules.base import BaseModule

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "returnurl", "goto", "target", "dest", "destination",
    "redir", "r", "u", "link", "forward", "location",
}

PROBE_URL = "https://erebus-redirect-probe.invalid/"


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class RedirectModule(BaseModule):
    name = "redirect"
    description = "Detects open redirect vulnerabilities in URL parameters"

    def run(self, urls: List[str], forms: List[dict]) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() not in REDIRECT_PARAMS:
                    continue
                test_url = _inject_param(url, param, PROBE_URL)
                try:
                    resp = self.get(test_url)
                except Exception:
                    continue

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "erebus-redirect-probe" in location:
                        key = (url, param)
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                module=self.name,
                                severity="medium",
                                title="Open Redirect",
                                url=test_url,
                                detail=f"Parameter '{param}' redirects to an arbitrary external URL without validation.",
                                evidence=f"Location header: {location!r}",
                                remediation="Validate redirect targets against an allowlist of trusted domains. Reject or encode user-supplied redirect URLs.",
                            ))

        return findings
