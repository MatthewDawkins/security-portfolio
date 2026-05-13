from typing import List
from src.models import Finding
from src.modules.base import BaseModule

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "title": "Missing HSTS Header",
        "detail": "HTTP Strict-Transport-Security is not set. Browsers may allow downgrade attacks to HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "title": "Missing Content-Security-Policy Header",
        "detail": "No CSP header found. The application may be vulnerable to XSS and data injection attacks.",
        "remediation": "Define a strict CSP policy. At minimum: Content-Security-Policy: default-src 'self'",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options Header",
        "detail": "X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff responses.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "title": "Missing X-Frame-Options Header",
        "detail": "X-Frame-Options is not set. The page may be embeddable in iframes, enabling clickjacking.",
        "remediation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed internally)",
    },
    "Referrer-Policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy Header",
        "detail": "No Referrer-Policy set. Full URLs may be leaked to third parties via the Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy Header",
        "detail": "No Permissions-Policy header. Browser features like camera and geolocation are unrestricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

INSECURE_HEADERS = {
    "Server": {
        "severity": "info",
        "title": "Server Version Disclosure",
        "detail": "The Server header reveals software version information that aids fingerprinting.",
        "remediation": "Remove or genericize the Server header in your web server configuration.",
    },
    "X-Powered-By": {
        "severity": "info",
        "title": "X-Powered-By Disclosure",
        "detail": "X-Powered-By reveals the backend technology stack.",
        "remediation": "Remove the X-Powered-By header.",
    },
}


class HeadersModule(BaseModule):
    name = "headers"
    description = "Checks for missing or insecure HTTP security headers"

    def run(self, urls: List[str], forms: List[dict]) -> List[Finding]:
        findings: List[Finding] = []
        if not urls:
            return findings

        target = urls[0]
        try:
            resp = self.get(target)
        except Exception:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append(Finding(
                    module=self.name,
                    severity=meta["severity"],
                    title=meta["title"],
                    url=target,
                    detail=meta["detail"],
                    remediation=meta["remediation"],
                ))

        for header, meta in INSECURE_HEADERS.items():
            value = headers.get(header.lower())
            if value:
                findings.append(Finding(
                    module=self.name,
                    severity=meta["severity"],
                    title=meta["title"],
                    url=target,
                    detail=f"{meta['detail']} Observed value: {value!r}",
                    remediation=meta["remediation"],
                ))

        return findings
