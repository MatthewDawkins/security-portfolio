from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.models import Finding
from src.modules.base import BaseModule

PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

UNIX_SIGNATURES = ["root:x:", "root:0:0", "daemon:x:"]
WIN_SIGNATURES = ["[extensions]", "[fonts]", "[mci extensions]"]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class TraversalModule(BaseModule):
    name = "traversal"
    description = "Detects path traversal vulnerabilities in URL parameters"

    def run(self, urls: List[str], forms: List[dict]) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in PAYLOADS:
                    test_url = _inject_param(url, param, payload)
                    try:
                        resp = self.get(test_url)
                        body = resp.text
                    except Exception:
                        continue
                    all_sigs = UNIX_SIGNATURES + WIN_SIGNATURES
                    for sig in all_sigs:
                        if sig in body:
                            key = (url, param)
                            if key not in seen:
                                seen.add(key)
                                findings.append(Finding(
                                    module=self.name,
                                    severity="critical",
                                    title="Path Traversal",
                                    url=test_url,
                                    detail=f"Parameter '{param}' allows directory traversal. File content was returned.",
                                    evidence=f"Matched file content signature: '{sig}'",
                                    remediation="Validate and canonicalize all file path inputs. Use an allowlist of permitted paths. Never pass user input directly to filesystem APIs.",
                                ))
                            break

        return findings
