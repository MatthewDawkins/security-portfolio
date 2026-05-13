"""
Reporter — generates the self-contained dark-theme HTML report.
"""

import html
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List

from src.models import Finding, SEVERITY_RANK

SEVERITY_BADGE = {
    "critical": ("#ff4444", "#2a0000"),
    "high":     ("#ff8800", "#2a1400"),
    "medium":   ("#ffcc00", "#2a2200"),
    "low":      ("#44aaff", "#001a2a"),
    "info":     ("#888888", "#1a1a1a"),
}

MITRE_BASE = "https://attack.mitre.org/techniques/"

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
  background: #0d1117; color: #c9d1d9; font-size: 14px; line-height: 1.6;
}
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }
.header { border-bottom: 1px solid #21262d; padding-bottom: 24px; margin-bottom: 32px; }
.header h1 { font-size: 28px; font-weight: 700; color: #f0f6fc; letter-spacing: -0.5px; }
.header h1 span { color: #58a6ff; }
.header .meta { color: #8b949e; font-size: 13px; margin-top: 8px; }
.header .meta strong { color: #c9d1d9; }
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin-bottom: 32px;
}
.summary-card {
  background: #161b22; border: 1px solid #21262d; border-radius: 8px;
  padding: 16px; text-align: center;
}
.summary-card .count { font-size: 36px; font-weight: 700; }
.summary-card .label { font-size: 12px; color: #8b949e; text-transform: uppercase;
  letter-spacing: 0.5px; margin-top: 4px; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
}
.service-breakdown {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px; margin-bottom: 32px;
}
.service-card {
  background: #161b22; border: 1px solid #21262d; border-radius: 8px;
  padding: 14px 16px;
}
.service-card .service-name { font-weight: 600; color: #f0f6fc; margin-bottom: 8px; }
.service-bar { display: flex; gap: 6px; flex-wrap: wrap; }
.section-title {
  font-size: 16px; font-weight: 600; color: #f0f6fc;
  margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #21262d;
}
.finding {
  background: #161b22; border: 1px solid #21262d; border-radius: 8px;
  margin-bottom: 12px; overflow: hidden;
}
.finding-header {
  display: flex; align-items: flex-start; gap: 12px;
  padding: 14px 16px; cursor: pointer;
}
.finding-header:hover { background: #1c2128; }
.finding-title { font-weight: 600; color: #f0f6fc; flex: 1; }
.finding-meta { font-size: 12px; color: #8b949e; margin-top: 3px; }
.finding-body { padding: 0 16px 16px 16px; border-top: 1px solid #21262d; }
.finding-body p { color: #c9d1d9; margin-top: 12px; }
.finding-body .label { font-size: 11px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.5px; color: #8b949e; margin-top: 14px; margin-bottom: 4px; }
.finding-body .value { color: #e6edf3; }
.finding-body code {
  background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
  padding: 1px 6px; font-family: monospace; font-size: 13px; color: #79c0ff;
}
.mitre-pill {
  display: inline-block; background: #1c2128; border: 1px solid #30363d;
  border-radius: 4px; padding: 3px 10px; font-size: 12px; color: #58a6ff;
  text-decoration: none; margin-top: 8px;
}
.mitre-pill:hover { background: #21262d; }
.check-id { font-family: monospace; font-size: 12px; color: #8b949e; white-space: nowrap; }
.toggle-icon { color: #8b949e; font-size: 16px; flex-shrink: 0; margin-top: 2px; }
details > summary { list-style: none; }
details > summary::-webkit-details-marker { display: none; }
.footer { margin-top: 48px; padding-top: 24px; border-top: 1px solid #21262d;
  color: #8b949e; font-size: 12px; text-align: center; }
"""

JS = """
// All findings start collapsed
document.querySelectorAll('details').forEach(d => d.removeAttribute('open'));
"""


def _badge(severity: str) -> str:
    fg, bg = SEVERITY_BADGE.get(severity.lower(), ("#888", "#1a1a1a"))
    return f'<span class="badge" style="color:{fg};background:{bg}">{html.escape(severity.upper())}</span>'


def _service_breakdown(findings: List[Finding]) -> str:
    by_service: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        by_service[f.service][f.severity.lower()] += 1

    cards = []
    for service in sorted(by_service.keys()):
        sev_counts = by_service[service]
        pills = ""
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts.get(sev, 0)
            if count:
                fg, bg = SEVERITY_BADGE[sev]
                pills += (
                    f'<span class="badge" style="color:{fg};background:{bg}">'
                    f'{count} {sev.upper()}</span> '
                )
        cards.append(
            f'<div class="service-card">'
            f'<div class="service-name">{html.escape(service)}</div>'
            f'<div class="service-bar">{pills}</div>'
            f'</div>'
        )
    return '<div class="service-breakdown">' + "".join(cards) + "</div>"


def _finding_html(finding: Finding) -> str:
    fg, bg = SEVERITY_BADGE.get(finding.severity.lower(), ("#888", "#1a1a1a"))
    badge = _badge(finding.severity)

    mitre_html = ""
    if finding.mitre_technique:
        tech_url = MITRE_BASE + finding.mitre_technique.replace(".", "/")
        mitre_html = (
            f'<a class="mitre-pill" href="{tech_url}" target="_blank">'
            f'{html.escape(finding.mitre_technique)}'
            f'{" — " + html.escape(finding.mitre_name) if finding.mitre_name else ""}'
            f'</a>'
        )

    return f"""
<details class="finding" style="border-left: 3px solid {fg}">
  <summary class="finding-header">
    <span class="check-id">{html.escape(finding.check_id)}</span>
    {badge}
    <div style="flex:1">
      <div class="finding-title">{html.escape(finding.title)}</div>
      <div class="finding-meta">
        {html.escape(finding.service)} &middot;
        <code>{html.escape(finding.resource_id)}</code> &middot;
        {html.escape(finding.region)}
      </div>
    </div>
    <span class="toggle-icon">&#9660;</span>
  </summary>
  <div class="finding-body">
    <div class="label">Description</div>
    <div class="value">{html.escape(finding.description)}</div>
    <div class="label">Recommendation</div>
    <div class="value">{html.escape(finding.recommendation)}</div>
    {('<div class="label">MITRE ATT&amp;CK</div>' + mitre_html) if mitre_html else ""}
  </div>
</details>"""


def generate_report(
    identity: dict,
    findings: List[Finding],
    output_path: str,
) -> None:
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    account_id = identity.get("account_id", "unknown")
    region     = identity.get("region", "unknown")
    arn        = identity.get("arn", "unknown")

    # Summary counts
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity.lower()] += 1
    total = len(findings)

    def card(sev: str) -> str:
        fg, bg = SEVERITY_BADGE[sev]
        n = counts.get(sev, 0)
        return (
            f'<div class="summary-card" style="border-top: 3px solid {fg}">'
            f'<div class="count" style="color:{fg}">{n}</div>'
            f'<div class="label">{sev.upper()}</div>'
            f'</div>'
        )

    summary_cards = (
        f'<div class="summary-card" style="border-top: 3px solid #58a6ff">'
        f'<div class="count" style="color:#58a6ff">{total}</div>'
        f'<div class="label">Total Findings</div>'
        f'</div>'
        + "".join(card(s) for s in ("critical", "high", "medium", "low", "info"))
    )

    findings_html = "".join(_finding_html(f) for f in findings)

    service_html = _service_breakdown(findings) if findings else "<p style='color:#8b949e'>No findings.</p>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aether — AWS Security Report — {html.escape(account_id)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1><span>Aether</span> — AWS Cloud Security Report</h1>
    <div class="meta">
      <strong>Account:</strong> {html.escape(account_id)} &nbsp;&middot;&nbsp;
      <strong>Region:</strong> {html.escape(region)} &nbsp;&middot;&nbsp;
      <strong>Identity:</strong> {html.escape(arn)} &nbsp;&middot;&nbsp;
      <strong>Scanned:</strong> {scanned_at}
    </div>
  </div>

  <div class="summary-grid">{summary_cards}</div>

  <div class="section-title">Findings by Service</div>
  {service_html}

  <div class="section-title">All Findings ({total})</div>
  {findings_html if findings_html else '<p style="color:#8b949e">No findings detected.</p>'}

  <div class="footer">
    Generated by <strong>Aether</strong> &mdash; AWS Cloud Security Scanner
  </div>

</div>
<script>{JS}</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
