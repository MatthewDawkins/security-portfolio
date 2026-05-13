from typing import List
from datetime import datetime, timezone
from src.models import Finding, SEVERITY_RANK

SEVERITY_CSS = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#44aaff",
    "info": "#888888",
}


def _badge(severity: str) -> str:
    color = SEVERITY_CSS.get(severity, "#aaa")
    return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def generate_report(
    target: str,
    urls: List[str],
    forms: List[dict],
    findings: List[Finding],
    output_path: str,
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 99))

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            color = SEVERITY_CSS[sev]
            summary_html += f'<div class="stat"><span style="color:{color};font-size:2rem;font-weight:700">{counts[sev]}</span><br><span style="color:#888;font-size:.8rem;text-transform:uppercase">{sev}</span></div>'

    findings_html = ""
    for f in sorted_findings:
        color = SEVERITY_CSS.get(f.severity, "#aaa")
        evidence_html = f'<div class="evidence"><strong>Evidence:</strong> {_escape(f.evidence)}</div>' if f.evidence else ""
        remediation_html = f'<div class="remediation"><strong>Remediation:</strong> {_escape(f.remediation)}</div>' if f.remediation else ""
        findings_html += f"""
        <div class="finding" style="border-left:3px solid {color}">
            <div class="finding-header">
                {_badge(f.severity)}
                <span class="finding-title">{_escape(f.title)}</span>
                <span class="finding-module">[{_escape(f.module)}]</span>
            </div>
            <div class="finding-url">{_escape(f.url)}</div>
            <div class="finding-detail">{_escape(f.detail)}</div>
            {evidence_html}
            {remediation_html}
        </div>"""

    if not findings_html:
        findings_html = '<div style="color:#666;padding:2rem 0">No findings detected.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Erebus Scan Report — {_escape(target)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d0d0d; color: #e0e0e0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  .header {{ border-bottom: 1px solid #222; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.6rem; font-weight: 700; color: #fff; }}
  .header h1 span {{ color: #7c3aed; }}
  .meta {{ color: #555; font-size: .85rem; margin-top: .4rem; }}
  .stats {{ display: flex; gap: 2rem; margin: 2rem 0; }}
  .stat {{ text-align: center; background: #111; border: 1px solid #1e1e1e; border-radius: 8px; padding: 1rem 1.5rem; }}
  .section-title {{ color: #888; font-size: .7rem; text-transform: uppercase; letter-spacing: .1em; margin: 2rem 0 1rem; }}
  .finding {{ background: #111; border-radius: 6px; padding: 1rem 1.2rem; margin-bottom: .75rem; }}
  .finding-header {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .5rem; }}
  .finding-title {{ font-weight: 600; color: #f0f0f0; }}
  .finding-module {{ color: #444; font-size: .8rem; }}
  .finding-url {{ font-family: monospace; font-size: .78rem; color: #555; margin-bottom: .4rem; word-break: break-all; }}
  .finding-detail {{ font-size: .88rem; color: #bbb; margin-bottom: .4rem; }}
  .evidence {{ font-size: .82rem; color: #777; font-family: monospace; margin-top: .3rem; }}
  .remediation {{ font-size: .82rem; color: #4ade80; margin-top: .4rem; }}
  .badge {{ font-size: .65rem; font-weight: 700; padding: .2em .55em; border-radius: 3px; color: #000; text-transform: uppercase; letter-spacing: .05em; }}
  .urls-list {{ font-family: monospace; font-size: .78rem; color: #555; line-height: 1.8; }}
  footer {{ margin-top: 3rem; color: #333; font-size: .75rem; border-top: 1px solid #1a1a1a; padding-top: 1rem; }}
</style>
</head>
<body>
<div class="header">
  <h1><span>Erebus</span> Vulnerability Scan Report</h1>
  <div class="meta">Target: {_escape(target)} &nbsp;|&nbsp; {now} &nbsp;|&nbsp; {len(urls)} URLs crawled &nbsp;|&nbsp; {len(forms)} forms found</div>
</div>

<div class="stats">
  {summary_html}
  <div class="stat"><span style="color:#e0e0e0;font-size:2rem;font-weight:700">{len(findings)}</span><br><span style="color:#888;font-size:.8rem;text-transform:uppercase">Total</span></div>
</div>

<div class="section-title">Findings</div>
{findings_html}

<div class="section-title">Crawled URLs ({len(urls)})</div>
<div class="urls-list">{'<br>'.join(_escape(u) for u in urls)}</div>

<footer>Generated by Erebus &nbsp;|&nbsp; For authorized security testing and educational use only.</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
