from typing import List
from urllib.parse import urljoin
from src.models import Finding
from src.modules.base import BaseModule

SENSITIVE_PATHS = [
    ("/.env", ["APP_KEY", "DB_PASSWORD", "SECRET_KEY", "AWS_SECRET"], "critical"),
    ("/.git/config", ["[core]", "[remote"], "high"),
    ("/wp-config.php", ["DB_PASSWORD", "DB_NAME", "table_prefix"], "critical"),
    ("/config.php", ["password", "db_pass", "mysql_pass"], "high"),
    ("/phpinfo.php", ["PHP Version", "phpinfo()"], "medium"),
    ("/server-status", ["Apache Server Status", "requests currently being processed"], "medium"),
    ("/actuator", ['"status"', '"health"'], "medium"),
    ("/actuator/env", ["propertySources", "systemProperties"], "high"),
    ("/actuator/mappings", ["mappings", "dispatcherServlets"], "medium"),
    ("/.DS_Store", ["\x00\x00\x00\x01"], "low"),
    ("/backup.zip", ["PK\x03\x04"], "high"),
    ("/db.sql", ["CREATE TABLE", "INSERT INTO"], "critical"),
    ("/dump.sql", ["CREATE TABLE", "INSERT INTO"], "critical"),
    ("/robots.txt", None, "info"),
    ("/sitemap.xml", None, "info"),
]


class ExposureModule(BaseModule):
    name = "exposure"
    description = "Checks for exposed sensitive files and endpoints"

    def run(self, urls: List[str], forms: List[dict]) -> List[Finding]:
        findings: List[Finding] = []
        if not urls:
            return findings

        base = urls[0]
        parsed_base = base.split("//", 1)
        if len(parsed_base) == 2:
            scheme_host = parsed_base[0] + "//" + parsed_base[1].split("/")[0]
        else:
            scheme_host = base

        for path, signatures, severity in SENSITIVE_PATHS:
            test_url = urljoin(scheme_host + "/", path.lstrip("/"))
            try:
                resp = self.get(test_url)
            except Exception:
                continue

            if resp.status_code not in (200, 206):
                continue

            body = resp.text

            if signatures is None:
                # Just report existence for informational paths
                findings.append(Finding(
                    module=self.name,
                    severity=severity,
                    title=f"Exposed File: {path}",
                    url=test_url,
                    detail=f"{path} is publicly accessible (HTTP {resp.status_code}).",
                    remediation=f"Restrict access to {path} via server configuration or remove it from the web root.",
                ))
                continue

            for sig in signatures:
                if sig in body:
                    findings.append(Finding(
                        module=self.name,
                        severity=severity,
                        title=f"Sensitive File Exposed: {path}",
                        url=test_url,
                        detail=f"{path} is publicly accessible and contains sensitive content.",
                        evidence=f"Matched signature: {sig!r}",
                        remediation=f"Remove or restrict access to {path}. Ensure secrets are not stored in web-accessible locations.",
                    ))
                    break

        return findings
