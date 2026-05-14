"""
DNS checks:
  STR-DNS-001  Missing SPF record (email spoofing risk)
  STR-DNS-002  Missing or inadequate DMARC record
  STR-DNS-003  Missing CAA record (certificate issuance control)
"""

from typing import List
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from src.checks.base import BaseCheck
from src.models import Finding


def _domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or url


class DNSChecks(BaseCheck):
    service = "DNS"

    def run(self, session, region: str, url: str = None) -> List[Finding]:
        if not url or not DNS_AVAILABLE:
            return []

        domain = _domain(url)
        findings: List[Finding] = []

        findings += self._check_spf(domain)
        findings += self._check_dmarc(domain)
        findings += self._check_caa(domain)

        return findings

    # ── STR-DNS-001 ────────────────────────────────────────────────────────────

    def _check_spf(self, domain: str) -> List[Finding]:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s
                              for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    # SPF exists — check for overly permissive +all
                    if "+all" in txt:
                        return [Finding(
                            check_id="STR-DNS-001",
                            title="SPF Record Uses +all (Permits All Senders)",
                            severity="high",
                            service="DNS",
                            resource_type="DNS Record",
                            resource_id=f"TXT {domain}",
                            region="dns",
                            description=(
                                f"The SPF record for '{domain}' ends with '+all', which means "
                                "any server in the world is authorised to send email on behalf "
                                "of this domain. This completely negates SPF protection and "
                                "makes the domain trivially spoofable."
                            ),
                            recommendation=(
                                f"Change '+all' to '-all' (fail) or '~all' (softfail): "
                                f"v=spf1 ... -all\n"
                                "Use '-all' for strict rejection or '~all' while transitioning "
                                "to DMARC enforcement."
                            ),
                            mitre_technique="T1566.002",
                            mitre_tactic="Initial Access",
                            mitre_name="Phishing - Spearphishing Link",
                        )]
                    return []  # SPF present and not overly permissive

            # No SPF record found
            return [Finding(
                check_id="STR-DNS-001",
                title="Missing SPF Record",
                severity="high",
                service="DNS",
                resource_type="DNS Record",
                resource_id=f"TXT {domain}",
                region="dns",
                description=(
                    f"No SPF TXT record was found for '{domain}'. "
                    "Without SPF, any mail server can send email claiming to be from this domain. "
                    "Attackers use this to send phishing and business email compromise (BEC) messages "
                    "that appear to come from your legitimate domain."
                ),
                recommendation=(
                    f"Add a TXT record to your DNS: v=spf1 include:_spf.yourmailprovider.com -all\n"
                    "Replace the include with your actual mail provider's SPF record. "
                    "Pair with DMARC to enforce policy."
                ),
                mitre_technique="T1566.002",
                mitre_tactic="Initial Access",
                mitre_name="Phishing - Spearphishing Link",
            )]
        except (dns.exception.DNSException, Exception):
            return []

    # ── STR-DNS-002 ────────────────────────────────────────────────────────────

    def _check_dmarc(self, domain: str) -> List[Finding]:
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s
                              for s in rdata.strings)
                if txt.startswith("v=DMARC1"):
                    # Check policy strength
                    policy = "none"
                    for tag in txt.split(";"):
                        tag = tag.strip()
                        if tag.lower().startswith("p="):
                            policy = tag.split("=")[1].strip().lower()

                    if policy == "none":
                        return [Finding(
                            check_id="STR-DNS-002",
                            title="DMARC Policy Set to 'none' (Monitor Only)",
                            severity="medium",
                            service="DNS",
                            resource_type="DNS Record",
                            resource_id=f"TXT {dmarc_domain}",
                            region="dns",
                            description=(
                                f"DMARC is configured for '{domain}' but the policy is p=none, "
                                "which means emails that fail SPF/DKIM checks are still delivered. "
                                "p=none only reports violations — it does not prevent email spoofing."
                            ),
                            recommendation=(
                                "Progress to p=quarantine (send failures to spam) and eventually "
                                "p=reject (block failures entirely). Monitor aggregate reports (rua=) "
                                "to understand your legitimate email sending before tightening policy."
                            ),
                            mitre_technique="T1566",
                            mitre_tactic="Initial Access",
                            mitre_name="Phishing",
                        )]
                    return []  # DMARC present with enforcement

            # No DMARC record
            return [Finding(
                check_id="STR-DNS-002",
                title="Missing DMARC Record",
                severity="high",
                service="DNS",
                resource_type="DNS Record",
                resource_id=f"TXT {dmarc_domain}",
                region="dns",
                description=(
                    f"No DMARC record was found at '_dmarc.{domain}'. "
                    "Without DMARC, receiving mail servers have no policy guidance for handling "
                    "emails that fail SPF or DKIM authentication, making your domain usable "
                    "for spoofed phishing campaigns."
                ),
                recommendation=(
                    f"Add a TXT record at '_dmarc.{domain}': "
                    "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com\n"
                    "Start with p=none to collect reports, then move to p=quarantine and p=reject."
                ),
                mitre_technique="T1566",
                mitre_tactic="Initial Access",
                mitre_name="Phishing",
            )]
        except (dns.exception.DNSException, Exception):
            return []

    # ── STR-DNS-003 ────────────────────────────────────────────────────────────

    def _check_caa(self, domain: str) -> List[Finding]:
        try:
            dns.resolver.resolve(domain, "CAA")
            return []  # CAA record exists
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            return []
        except Exception:
            return []

        return [Finding(
            check_id="STR-DNS-003",
            title="Missing CAA Record",
            severity="low",
            service="DNS",
            resource_type="DNS Record",
            resource_id=f"CAA {domain}",
            region="dns",
            description=(
                f"No CAA (Certification Authority Authorization) record exists for '{domain}'. "
                "Without CAA, any trusted certificate authority can issue a TLS certificate "
                "for your domain. A misissuance event (CA compromise or social engineering) "
                "could result in an attacker obtaining a valid certificate for your domain."
            ),
            recommendation=(
                f"Add a CAA record restricting issuance to your CA(s). "
                "For AWS ACM (which uses Amazon Trust Services / DigiCert): "
                f"{domain}. CAA 0 issue \"amazon.com\"\n"
                f"{domain}. CAA 0 issue \"amazontrust.com\""
            ),
        )]
