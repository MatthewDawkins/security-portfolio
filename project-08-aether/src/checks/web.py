"""
Web / HTTP / TLS checks:
  STR-WEB-001  HTTPS not enforced (HTTP does not redirect to HTTPS)
  STR-WEB-002  Missing HTTP Strict Transport Security (HSTS) header
  STR-WEB-003  Missing Content-Security-Policy header
  STR-WEB-004  Missing X-Frame-Options header
  STR-WEB-005  Missing X-Content-Type-Options header
  STR-WEB-006  Server version disclosed in response headers
  STR-WEB-007  CORS wildcard (Access-Control-Allow-Origin: *)
  STR-WEB-008  TLS certificate expiring within 30 days or already expired
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from src.checks.base import BaseCheck
from src.models import Finding

TIMEOUT = 10
HEADERS = {"User-Agent": "Aether-Security-Scanner/1.0"}


def _hostname(url: str) -> str:
    return urlparse(url).hostname or url


def _https_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(scheme="https").geturl()


def _http_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(scheme="http").geturl()


class WebChecks(BaseCheck):
    service = "Web"

    def run(self, session, region: str, url: str = None) -> List[Finding]:
        if not url:
            return []

        hostname = _hostname(url)
        findings: List[Finding] = []

        # Fetch over HTTPS for header checks
        https_response = None
        try:
            https_response = requests.get(
                _https_url(url), headers=HEADERS, timeout=TIMEOUT,
                allow_redirects=True, verify=True,
            )
        except RequestException:
            pass

        findings += self._check_https_redirect(url, hostname)
        findings += self._check_tls_cert(hostname)

        if https_response is not None:
            resp_headers = https_response.headers
            findings += self._check_hsts(resp_headers, hostname)
            findings += self._check_csp(resp_headers, hostname)
            findings += self._check_x_frame_options(resp_headers, hostname)
            findings += self._check_x_content_type(resp_headers, hostname)
            findings += self._check_server_disclosure(resp_headers, hostname)
            findings += self._check_cors_wildcard(resp_headers, hostname)

        return findings

    # ── STR-WEB-001 ────────────────────────────────────────────────────────────

    def _check_https_redirect(self, url: str, hostname: str) -> List[Finding]:
        http_url = _http_url(url)
        try:
            resp = requests.get(
                http_url, headers=HEADERS, timeout=TIMEOUT,
                allow_redirects=False, verify=False,
            )
            # Should be a 3xx redirect to https://
            if resp.status_code not in (301, 302, 307, 308):
                return [Finding(
                    check_id="STR-WEB-001",
                    title="HTTPS Not Enforced",
                    severity="high",
                    service="Web",
                    resource_type="Website",
                    resource_id=hostname,
                    region="web",
                    description=(
                        f"HTTP requests to '{http_url}' return status {resp.status_code} "
                        "instead of a redirect to HTTPS. Users who type the bare domain "
                        "or follow an HTTP link are served content over an unencrypted connection, "
                        "exposing credentials, session tokens, and data to interception."
                    ),
                    recommendation=(
                        "Configure your web server or load balancer to redirect all HTTP "
                        "traffic to HTTPS with a 301 permanent redirect. "
                        "For CloudFront: Viewer Protocol Policy → Redirect HTTP to HTTPS."
                    ),
                    mitre_technique="T1557.001",
                    mitre_tactic="Credential Access",
                    mitre_name="Adversary-in-the-Middle - LLMNR/NBT-NS Poisoning",
                )]
            location = resp.headers.get("Location", "")
            if not location.startswith("https://"):
                return [Finding(
                    check_id="STR-WEB-001",
                    title="HTTPS Redirect Does Not Use HTTPS Destination",
                    severity="high",
                    service="Web",
                    resource_type="Website",
                    resource_id=hostname,
                    region="web",
                    description=(
                        f"HTTP requests to '{http_url}' redirect to '{location}' "
                        "which does not begin with https://. The redirect target is not secure."
                    ),
                    recommendation=(
                        "Ensure the HTTP redirect target URL uses the https:// scheme."
                    ),
                    mitre_technique="T1557.001",
                    mitre_tactic="Credential Access",
                    mitre_name="Adversary-in-the-Middle",
                )]
        except RequestException:
            pass
        return []

    # ── STR-WEB-002 ────────────────────────────────────────────────────────────

    def _check_hsts(self, headers: dict, hostname: str) -> List[Finding]:
        hsts = headers.get("Strict-Transport-Security", "")
        if not hsts:
            return [Finding(
                check_id="STR-WEB-002",
                title="Missing HTTP Strict Transport Security (HSTS) Header",
                severity="medium",
                service="Web",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' does not set the Strict-Transport-Security header. "
                    "Without HSTS, browsers will not automatically upgrade HTTP connections "
                    "to HTTPS on subsequent visits, leaving users vulnerable to SSL stripping attacks."
                ),
                recommendation=(
                    "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                    "Start with a short max-age (e.g. 300) to test, then increase to 31536000 (1 year). "
                    "Submit to the HSTS preload list at hstspreload.org after stabilising."
                ),
                mitre_technique="T1557.001",
                mitre_tactic="Credential Access",
                mitre_name="Adversary-in-the-Middle",
            )]
        # Check for short max-age
        try:
            for part in hsts.split(";"):
                part = part.strip()
                if part.lower().startswith("max-age="):
                    age = int(part.split("=")[1])
                    if age < 31536000:
                        return [Finding(
                            check_id="STR-WEB-002",
                            title="HSTS max-age Below Recommended Value",
                            severity="low",
                            service="Web",
                            resource_type="Website",
                            resource_id=hostname,
                            region="web",
                            description=(
                                f"HSTS is set but max-age={age} ({age//86400} days) is below "
                                "the recommended 31536000 (1 year). Short max-age values reduce "
                                "protection against SSL stripping between visits."
                            ),
                            recommendation=(
                                "Increase max-age to 31536000 (1 year) or higher. "
                                "Also add includeSubDomains and preload directives."
                            ),
                        )]
        except (ValueError, IndexError):
            pass
        return []

    # ── STR-WEB-003 ────────────────────────────────────────────────────────────

    def _check_csp(self, headers: dict, hostname: str) -> List[Finding]:
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            return [Finding(
                check_id="STR-WEB-003",
                title="Missing Content-Security-Policy Header",
                severity="medium",
                service="Web",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' does not set a Content-Security-Policy header. "
                    "Without CSP, browsers do not restrict which scripts, styles, or resources "
                    "can be loaded, making the site significantly more vulnerable to XSS attacks."
                ),
                recommendation=(
                    "Define a Content-Security-Policy appropriate for your application. "
                    "Start with a report-only policy to identify violations: "
                    "Content-Security-Policy-Report-Only: default-src 'self'\n"
                    "Then enforce. Avoid unsafe-inline and unsafe-eval in script-src."
                ),
                mitre_technique="T1059.007",
                mitre_tactic="Execution",
                mitre_name="Command and Scripting Interpreter - JavaScript",
            )]
        # Warn on unsafe-inline in script-src
        if "unsafe-inline" in csp.lower() and "script-src" in csp.lower():
            return [Finding(
                check_id="STR-WEB-003",
                title="Content-Security-Policy Allows unsafe-inline Scripts",
                severity="medium",
                service="Web",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' sets a CSP but allows 'unsafe-inline' in script-src. "
                    "This effectively negates XSS protection since inline scripts — "
                    "the most common XSS payload vehicle — are permitted."
                ),
                recommendation=(
                    "Remove 'unsafe-inline' from script-src. "
                    "Use nonces or hashes to allow specific inline scripts instead. "
                    "Refactor inline event handlers to external scripts."
                ),
                mitre_technique="T1059.007",
                mitre_tactic="Execution",
                mitre_name="Command and Scripting Interpreter - JavaScript",
            )]
        return []

    # ── STR-WEB-004 ────────────────────────────────────────────────────────────

    def _check_x_frame_options(self, headers: dict, hostname: str) -> List[Finding]:
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")
        # Acceptable if set via X-Frame-Options OR CSP frame-ancestors
        if not xfo and "frame-ancestors" not in csp.lower():
            return [Finding(
                check_id="STR-WEB-004",
                title="Missing X-Frame-Options / CSP frame-ancestors Header",
                severity="medium",
                service="Web",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' does not set X-Frame-Options or CSP frame-ancestors. "
                    "Without this protection, the site can be embedded in an iframe on a "
                    "malicious page and used to perform clickjacking attacks against authenticated users."
                ),
                recommendation=(
                    "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed). "
                    "Prefer CSP frame-ancestors for more control: "
                    "Content-Security-Policy: frame-ancestors 'none'"
                ),
            )]
        return []

    # ── STR-WEB-005 ────────────────────────────────────────────────────────────

    def _check_x_content_type(self, headers: dict, hostname: str) -> List[Finding]:
        xcto = headers.get("X-Content-Type-Options", "")
        if xcto.strip().lower() != "nosniff":
            return [Finding(
                check_id="STR-WEB-005",
                title="Missing X-Content-Type-Options: nosniff Header",
                severity="low",
                service="Web",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' does not set X-Content-Type-Options: nosniff. "
                    "Without this header, browsers may MIME-sniff responses and execute "
                    "content as a different type than declared, enabling certain XSS and "
                    "drive-by download attacks."
                ),
                recommendation=(
                    "Add the header: X-Content-Type-Options: nosniff\n"
                    "This is a single-line change in any web server or CDN configuration."
                ),
            )]
        return []

    # ── STR-WEB-006 ────────────────────────────────────────────────────────────

    def _check_server_disclosure(self, headers: dict, hostname: str) -> List[Finding]:
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")

        disclosures = []
        # Flag if Server header contains version numbers or specific technology names
        import re
        if server and re.search(r"[\d.]+|nginx|apache|iis|gunicorn|uvicorn|tornado", server, re.I):
            disclosures.append(f"Server: {server}")
        if x_powered:
            disclosures.append(f"X-Powered-By: {x_powered}")

        if disclosures:
            return [Finding(
                check_id="STR-WEB-006",
                title="Server Technology Version Disclosed in Headers",
                severity="low",
                service="Web",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' discloses server technology in response headers: "
                    + "; ".join(disclosures) + ". "
                    "Version information assists attackers in identifying known CVEs and "
                    "targeting specific exploits."
                ),
                recommendation=(
                    "Remove or suppress version information from response headers. "
                    "For nginx: server_tokens off; "
                    "For Apache: ServerTokens Prod; ServerSignature Off; "
                    "Remove X-Powered-By entirely — it provides no user-facing value."
                ),
                mitre_technique="T1592.002",
                mitre_tactic="Reconnaissance",
                mitre_name="Gather Victim Host Information - Software",
            )]
        return []

    # ── STR-WEB-007 ────────────────────────────────────────────────────────────

    def _check_cors_wildcard(self, headers: dict, hostname: str) -> List[Finding]:
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao.strip() == "*":
            return [Finding(
                check_id="STR-WEB-007",
                title="CORS Wildcard: Access-Control-Allow-Origin: *",
                severity="medium",
                service="Web",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' returns Access-Control-Allow-Origin: * on all responses. "
                    "This allows any website to make cross-origin requests and read the responses. "
                    "If this endpoint serves authenticated data or session-dependent content, "
                    "it may expose sensitive information to malicious third-party sites."
                ),
                recommendation=(
                    "Replace the wildcard with an explicit allowlist of trusted origins. "
                    "If public API responses contain no user-specific data, a wildcard may be "
                    "acceptable — but verify no authentication-dependent endpoints share this policy."
                ),
            )]
        return []

    # ── STR-WEB-008 ────────────────────────────────────────────────────────────

    def _check_tls_cert(self, hostname: str) -> List[Finding]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            not_after_str = cert.get("notAfter", "")
            if not not_after_str:
                return []

            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (not_after - now).days

            if days_remaining <= 0:
                return [Finding(
                    check_id="STR-WEB-008",
                    title="TLS Certificate Expired",
                    severity="critical",
                    service="Web",
                    resource_type="TLS Certificate",
                    resource_id=hostname,
                    region="web",
                    description=(
                        f"The TLS certificate for '{hostname}' expired on "
                        f"{not_after.strftime('%Y-%m-%d')}. "
                        "Browsers will show a security warning and block access for all users."
                    ),
                    recommendation=(
                        "Renew the certificate immediately. "
                        "If using ACM with CloudFront/ALB, certificates renew automatically — "
                        "check that auto-renewal is enabled and DNS validation records are in place."
                    ),
                )]

            if days_remaining <= 30:
                return [Finding(
                    check_id="STR-WEB-008",
                    title=f"TLS Certificate Expiring in {days_remaining} Days",
                    severity="high" if days_remaining <= 14 else "medium",
                    service="Web",
                    resource_type="TLS Certificate",
                    resource_id=hostname,
                    region="web",
                    description=(
                        f"The TLS certificate for '{hostname}' expires on "
                        f"{not_after.strftime('%Y-%m-%d')} ({days_remaining} days remaining). "
                        "An expired certificate causes browser warnings and breaks HTTPS for all users."
                    ),
                    recommendation=(
                        "Renew the certificate before expiry. "
                        "For ACM-managed certificates, verify auto-renewal is enabled. "
                        "Set up expiry monitoring/alerting (e.g. CloudWatch, Datadog) to avoid future lapses."
                    ),
                )]
        except (ssl.SSLError, socket.error, OSError):
            pass
        return []
