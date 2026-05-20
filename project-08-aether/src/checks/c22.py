"""
Bill C-22 (Lawful Access Act) compliance checks.

These checks identify metadata collection and retention practices on a target
website that are directly relevant to Canada's Bill C-22 obligations.

Bill C-22 requires "electronic service providers" operating in Canada to:
  - Retain transmission metadata (timestamps, IPs, device IDs, location) for up to 1 year
  - Build technical capabilities enabling law enforcement data extraction on demand
  - Comply with ministerial orders to disclose subscriber information

These checks help Canadian businesses understand what metadata they currently
collect or expose, what third parties receive that data, and where gaps in
privacy controls create compliance and surveillance-exposure risk.

Checks:
  C22-WEB-001  Missing or Permissive Referrer-Policy
  C22-WEB-002  Third-Party Tracking Scripts Detected
  C22-WEB-003  Persistent Tracking Cookies Without SameSite=Strict
  C22-WEB-004  Geolocation API Not Restricted (Permissions-Policy)
  C22-WEB-005  No Accessible Privacy Policy Page Detected
  C22-WEB-006  Third-Party CDN / Infrastructure Detected (Data Residency Risk)
"""

import re
from typing import List
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from src.checks.base import BaseCheck
from src.models import Finding

TIMEOUT = 10
HEADERS = {"User-Agent": "Aether-Security-Scanner/1.0"}

# Known third-party analytics and tracking domains
TRACKING_DOMAINS = [
    "google-analytics.com",
    "googletagmanager.com",
    "analytics.google.com",
    "connect.facebook.net",
    "facebook.com",
    "doubleclick.net",
    "hotjar.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "amplitude.com",
    "heap.io",
    "clarity.ms",
    "matomo.cloud",
    "mouseflow.com",
]

# Privacy policy URL paths to probe, in order
PRIVACY_PATHS = [
    "/privacy",
    "/privacy-policy",
    "/privacy_policy",
    "/legal/privacy",
    "/en/privacy",
    "/about/privacy",
    "/policies/privacy",
]

# Response header fingerprints that reveal CDN/hosting provider
CDN_FINGERPRINTS = [
    ("CF-Ray",                  "Cloudflare (US-based CDN)"),
    ("x-amz-cf-id",             "AWS CloudFront (US-based CDN)"),
    ("X-Vercel-Id",             "Vercel (US-based platform)"),
    ("Fly-Request-Id",          "Fly.io (US-based platform)"),
    ("X-Render-Origin-Server",  "Render (US-based platform)"),
    ("X-Served-By",             "Fastly (US-based CDN)"),
    ("X-Cache",                 "CDN cache layer (provider unknown)"),
    ("X-Cache-Hits",            "CDN cache layer"),
]

# Referrer-Policy values that leak user navigation paths to third parties
PERMISSIVE_REFERRER_VALUES = {
    "",
    "unsafe-url",
    "no-referrer-when-downgrade",
    "origin-when-cross-origin",
}

THIRTY_DAYS_SECONDS = 30 * 24 * 3600


def _hostname(url: str) -> str:
    return urlparse(url).hostname or url


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _https_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(scheme="https").geturl()


def _get_all_set_cookie_headers(response: requests.Response) -> List[str]:
    """Return all Set-Cookie header values from the response."""
    try:
        return response.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw = response.headers.get("Set-Cookie", "")
        return [raw] if raw else []


class C22Checks(BaseCheck):
    service = "C-22"

    def run(self, session, region: str, url: str = None) -> List[Finding]:
        if not url:
            return []

        hostname = _hostname(url)
        findings: List[Finding] = []

        try:
            response = requests.get(
                _https_url(url),
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=True,
            )
        except RequestException:
            return []

        resp_headers = response.headers

        findings += self._check_referrer_policy(resp_headers, hostname)
        findings += self._check_tracking_scripts(resp_headers, response.text, hostname)
        findings += self._check_tracking_cookies(response, hostname)
        findings += self._check_geolocation_permission(resp_headers, hostname)
        findings += self._check_privacy_policy(url, hostname)
        findings += self._check_cdn_disclosure(resp_headers, hostname)

        return findings

    # ── C22-WEB-001 ────────────────────────────────────────────────────────────

    def _check_referrer_policy(self, headers: dict, hostname: str) -> List[Finding]:
        policy = headers.get("Referrer-Policy", "").strip().lower()

        if policy not in PERMISSIVE_REFERRER_VALUES:
            return []

        if not policy:
            detail = (
                "No Referrer-Policy header is set. Browsers default to "
                "'no-referrer-when-downgrade', which sends the full page URL "
                "as the Referer header to every HTTPS third-party resource loaded "
                "by your site — including analytics, fonts, and ad networks."
            )
        else:
            detail = (
                f"Referrer-Policy is set to '{policy}', which sends user navigation "
                "URLs to third-party domains on every page load."
            )

        return [Finding(
            check_id="C22-WEB-001",
            title="Missing or Permissive Referrer-Policy Header",
            severity="high",
            service="C-22",
            resource_type="Website",
            resource_id=hostname,
            region="web",
            description=(
                f"'{hostname}' has a permissive referrer policy. {detail} "
                "Under Bill C-22, navigation URL data is classified as 'transmission data' "
                "— a category of metadata that electronic service providers may be required "
                "to retain for up to one year and disclose to law enforcement on demand. "
                "A permissive referrer policy means your site is actively generating and "
                "distributing this metadata to third parties outside your control."
            ),
            recommendation=(
                "Set the header to restrict referrer leakage:\n"
                "  Referrer-Policy: no-referrer\n"
                "Or, for analytics compatibility that still protects path-level data:\n"
                "  Referrer-Policy: strict-origin-when-cross-origin\n"
                "This stops user navigation paths from being transmitted to third parties "
                "and reduces the scope of transmission metadata your site generates."
            ),
        )]

    # ── C22-WEB-002 ────────────────────────────────────────────────────────────

    def _check_tracking_scripts(
        self, headers: dict, body: str, hostname: str
    ) -> List[Finding]:
        found: set = set()

        # Check CSP script-src for explicitly whitelisted tracker domains
        csp = headers.get("Content-Security-Policy", "").lower()
        for domain in TRACKING_DOMAINS:
            if domain in csp:
                found.add(domain)

        # Check HTML body for <script src="..."> tags pointing to tracker domains
        script_srcs = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE
        )
        for src in script_srcs:
            for domain in TRACKING_DOMAINS:
                if domain in src.lower():
                    found.add(domain)

        if not found:
            return []

        return [Finding(
            check_id="C22-WEB-002",
            title="Third-Party Tracking Scripts Detected",
            severity="high",
            service="C-22",
            resource_type="Website",
            resource_id=hostname,
            region="web",
            description=(
                f"'{hostname}' loads third-party tracking or analytics scripts from: "
                f"{', '.join(sorted(found))}. "
                "These services receive user metadata — including IP addresses, session "
                "timing, device identifiers, and browsing behaviour — directly from your "
                "users' browsers. Under Bill C-22, this metadata may be retained by those "
                "third parties (many US-based) and subject to law enforcement disclosure "
                "requests that you have no visibility into or control over. A C-22 order "
                "directed at your organization may require you to hand over data you have "
                "already distributed to services you don't control."
            ),
            recommendation=(
                "Audit whether each tracking service is necessary for core functionality. "
                "Consider replacing US-hosted analytics with self-hosted, privacy-respecting "
                "alternatives (e.g. Plausible, Umami, or Matomo) that keep data within "
                "Canadian jurisdiction and under your control. "
                "Remove any trackers that are not strictly required. "
                "For trackers you retain, ensure your privacy policy discloses the data "
                "flows, the third-party identity, and their data retention period."
            ),
        )]

    # ── C22-WEB-003 ────────────────────────────────────────────────────────────

    def _check_tracking_cookies(
        self, response: requests.Response, hostname: str
    ) -> List[Finding]:
        set_cookie_headers = _get_all_set_cookie_headers(response)
        persistent: List[str] = []

        for cookie_str in set_cookie_headers:
            cookie_lower = cookie_str.lower()

            max_age_match = re.search(r"max-age\s*=\s*(\d+)", cookie_lower)
            if not max_age_match:
                continue
            if int(max_age_match.group(1)) <= THIRTY_DAYS_SECONDS:
                continue

            # Long-lived cookie — flag if not SameSite=Strict
            if "samesite=strict" not in cookie_lower:
                name = cookie_str.split("=")[0].strip()
                if name:
                    persistent.append(name)

        if not persistent:
            return []

        names_display = ", ".join(persistent[:5])
        if len(persistent) > 5:
            names_display += f" (+{len(persistent) - 5} more)"

        return [Finding(
            check_id="C22-WEB-003",
            title="Persistent Tracking Cookies Without SameSite=Strict",
            severity="high",
            service="C-22",
            resource_type="Website",
            resource_id=hostname,
            region="web",
            description=(
                f"'{hostname}' sets {len(persistent)} persistent cookie(s) that survive "
                f"more than 30 days and lack SameSite=Strict: {names_display}. "
                "Long-lived cookies create persistent user identifiers that constitute "
                "retained metadata under Bill C-22 — specifically the 'identifier of the "
                "device' category that the bill requires to be retainable for up to one year. "
                "Without SameSite=Strict, these identifiers are also transmitted in "
                "cross-site requests, enabling cross-domain user tracking and broadening "
                "the metadata footprint associated with each user."
            ),
            recommendation=(
                "Reduce cookie max-age to the minimum your application requires. "
                "Set SameSite=Strict on all authentication and session cookies. "
                "Use SameSite=Lax as a minimum for any remaining cookies. "
                "Audit each long-lived cookie — if used for analytics or personalisation, "
                "assess whether it can be replaced with a server-side session that does "
                "not create a persistent client-side identifier."
            ),
        )]

    # ── C22-WEB-004 ────────────────────────────────────────────────────────────

    def _check_geolocation_permission(
        self, headers: dict, hostname: str
    ) -> List[Finding]:
        policy = headers.get("Permissions-Policy", "").lower()

        if not policy:
            return [Finding(
                check_id="C22-WEB-004",
                title="Geolocation API Not Restricted — Permissions-Policy Missing",
                severity="high",
                service="C-22",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' does not set a Permissions-Policy header. "
                    "This means any script running on the page — including third-party "
                    "analytics or ad code — can request access to the user's device location "
                    "via the browser Geolocation API without restriction. "
                    "Device location data is explicitly named in Bill C-22 as a category "
                    "of retained metadata: the bill mandates retention of 'information that "
                    "identifies the location of the device,' which can be used to reconstruct "
                    "a person's physical movements over a one-year period."
                ),
                recommendation=(
                    "Add a Permissions-Policy header that disables location access by default:\n"
                    "  Permissions-Policy: geolocation=(), camera=(), microphone=()\n"
                    "If geolocation is required for a specific feature (e.g. a store locator), "
                    "restrict it to your own origin only:\n"
                    "  Permissions-Policy: geolocation=(self)"
                ),
            )]

        # Header is present — check whether geolocation is explicitly restricted
        geo_restricted = (
            "geolocation=()" in policy
            or "geolocation=(self)" in policy
            or "geolocation=self" in policy
        )
        if not geo_restricted:
            return [Finding(
                check_id="C22-WEB-004",
                title="Geolocation API Not Explicitly Restricted in Permissions-Policy",
                severity="medium",
                service="C-22",
                resource_type="Website",
                resource_id=hostname,
                region="web",
                description=(
                    f"'{hostname}' sets a Permissions-Policy header but does not explicitly "
                    "restrict the Geolocation API. Third-party scripts may still be able to "
                    "request device location data. Under Bill C-22, device location is a "
                    "named category of retainable transmission metadata."
                ),
                recommendation=(
                    "Add geolocation=() to your Permissions-Policy to disable it entirely:\n"
                    "  Permissions-Policy: geolocation=(), ...\n"
                    "Or restrict it to your own origin: Permissions-Policy: geolocation=(self)"
                ),
            )]

        return []

    # ── C22-WEB-005 ────────────────────────────────────────────────────────────

    def _check_privacy_policy(self, url: str, hostname: str) -> List[Finding]:
        base = _base_url(url)

        for path in PRIVACY_PATHS:
            try:
                resp = requests.get(
                    base + path,
                    headers=HEADERS,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                    verify=True,
                )
                if resp.status_code == 200 and len(resp.content) > 500:
                    return []  # Found a real privacy policy page
            except RequestException:
                continue

        return [Finding(
            check_id="C22-WEB-005",
            title="No Accessible Privacy Policy Page Detected",
            severity="medium",
            service="C-22",
            resource_type="Website",
            resource_id=hostname,
            region="web",
            description=(
                f"No privacy policy page was found at common paths on '{hostname}' "
                f"(checked: {', '.join(PRIVACY_PATHS[:4])}, and others). "
                "Bill C-22 and PIPEDA require electronic service providers to disclose "
                "their data collection, retention, and disclosure practices to users. "
                "Without an accessible privacy policy, your site cannot meet the "
                "transparency obligations that accompany C-22's metadata retention regime, "
                "and cannot obtain informed consent for the data practices it imposes."
            ),
            recommendation=(
                "Publish a privacy policy that clearly describes:\n"
                "  • What metadata you collect (IPs, session data, device identifiers)\n"
                "  • How long you retain each category and why\n"
                "  • Whether you use third-party processors, who they are, and where they operate\n"
                "  • The legal basis for retention under Canadian law (PIPEDA / C-22)\n"
                "  • How users can request deletion or access to their data\n"
                "Link it from your site footer, any cookie consent banner, and all signup flows."
            ),
        )]

    # ── C22-WEB-006 ────────────────────────────────────────────────────────────

    def _check_cdn_disclosure(self, headers: dict, hostname: str) -> List[Finding]:
        header_keys_lower = {k.lower() for k in headers.keys()}

        for header_name, provider_name in CDN_FINGERPRINTS:
            if header_name.lower() in header_keys_lower:
                return [Finding(
                    check_id="C22-WEB-006",
                    title=f"Third-Party Infrastructure Detected: {provider_name}",
                    severity="info",
                    service="C-22",
                    resource_type="Website",
                    resource_id=hostname,
                    region="web",
                    description=(
                        f"'{hostname}' is served through {provider_name}, identified via "
                        f"response headers. Under Bill C-22, a ministerial disclosure order "
                        "would be directed at your organization — but your ability to comply, "
                        "and your users' data exposure, depends on where that provider stores "
                        "and processes request metadata (IP addresses, timestamps, request paths). "
                        "US-based providers are subject to US law (FISA 702, National Security "
                        "Letters) independently of any Canadian legal process, meaning your users' "
                        "data may be accessible to US authorities without your knowledge."
                    ),
                    recommendation=(
                        "Review your infrastructure provider's data residency options. "
                        "Canadian-region configurations (e.g. AWS ca-central-1, ca-west-1; "
                        "Cloudflare Data Localization Suite) can reduce cross-border data exposure. "
                        "Regardless of provider, document your infrastructure stack and data "
                        "flows in your privacy policy so users can make informed decisions."
                    ),
                )]

        return []
