from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.models import Finding
from src.modules.base import BaseModule

PAYLOADS = ["'", "''", "`", "1'1", "1 OR 1=1", "' OR '1'='1"]

ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3.operationalerror",
    "syntax error in query",
    "you have an error in your sql syntax",
    "warning: mysql",
    "invalid query",
    "supplied argument is not a valid mysql",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "jdbc",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class SQLIModule(BaseModule):
    name = "sqli"
    description = "Detects error-based SQL injection in URL parameters and forms"

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
                        body = resp.text.lower()
                    except Exception:
                        continue
                    for sig in ERROR_SIGNATURES:
                        if sig in body:
                            key = (url, param)
                            if key not in seen:
                                seen.add(key)
                                findings.append(Finding(
                                    module=self.name,
                                    severity="high",
                                    title="SQL Injection (Error-Based)",
                                    url=test_url,
                                    detail=f"Parameter '{param}' triggered a database error with payload: {payload!r}",
                                    evidence=f"Matched signature: '{sig}'",
                                    remediation="Use parameterized queries or prepared statements. Never interpolate user input into SQL.",
                                ))
                            break

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = form.get("inputs", [])
            for inp in inputs:
                name = inp.get("name", "")
                if not name:
                    continue
                for payload in PAYLOADS:
                    data = {i.get("name", ""): i.get("value", "") for i in inputs}
                    data[name] = payload
                    try:
                        if method == "post":
                            resp = self.post(action, data=data)
                        else:
                            resp = self.get(action, params=data)
                        body = resp.text.lower()
                    except Exception:
                        continue
                    for sig in ERROR_SIGNATURES:
                        if sig in body:
                            key = (action, name)
                            if key not in seen:
                                seen.add(key)
                                findings.append(Finding(
                                    module=self.name,
                                    severity="high",
                                    title="SQL Injection (Error-Based, Form)",
                                    url=action,
                                    detail=f"Form field '{name}' triggered a database error with payload: {payload!r}",
                                    evidence=f"Matched signature: '{sig}'",
                                    remediation="Use parameterized queries or prepared statements. Never interpolate user input into SQL.",
                                ))
                            break

        return findings
