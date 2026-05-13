from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.models import Finding
from src.modules.base import BaseModule

PROBE = "<script>erebus_xss_probe</script>"
REFLECTED_MARKER = "erebus_xss_probe"


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class XSSModule(BaseModule):
    name = "xss"
    description = "Detects reflected XSS in URL parameters and forms"

    def run(self, urls: List[str], forms: List[dict]) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                test_url = _inject_param(url, param, PROBE)
                try:
                    resp = self.get(test_url)
                    if REFLECTED_MARKER in resp.text:
                        key = (url, param)
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                module=self.name,
                                severity="high",
                                title="Reflected XSS",
                                url=test_url,
                                detail=f"Parameter '{param}' reflects unsanitized input back into the response.",
                                evidence=f"Probe string found unescaped in response body.",
                                remediation="HTML-encode all user-supplied output. Use a Content-Security-Policy to restrict inline scripts.",
                            ))
                except Exception:
                    continue

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.get("inputs", [])
            for inp in inputs:
                name = inp.get("name", "")
                if not name:
                    continue
                data = {i.get("name", ""): i.get("value", "") for i in inputs}
                data[name] = PROBE
                try:
                    if method == "post":
                        resp = self.post(action, data=data)
                    else:
                        resp = self.get(action, params=data)
                    if REFLECTED_MARKER in resp.text:
                        key = (action, name)
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                module=self.name,
                                severity="high",
                                title="Reflected XSS (Form)",
                                url=action,
                                detail=f"Form field '{name}' reflects unsanitized input into the response.",
                                evidence="Probe string found unescaped in response body.",
                                remediation="HTML-encode all user-supplied output. Use a Content-Security-Policy to restrict inline scripts.",
                            ))
                except Exception:
                    continue

        return findings
