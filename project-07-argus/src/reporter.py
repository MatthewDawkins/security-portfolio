from datetime import datetime, timezone
from typing import List

from src.models import Alert, LogEvent
from src import mitre as mitre_db

LEVEL_CSS = {
    "critical":    "#ff4444",
    "high":        "#ff8800",
    "medium":      "#ffcc00",
    "low":         "#44aaff",
    "informational": "#888888",
}

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Command and Control", "Exfiltration",
]


def _escape(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


def _badge(level: str) -> str:
    color = LEVEL_CSS.get(level, "#aaa")
    return (
        f'<span style="background:{color};color:#000;font-size:.62rem;font-weight:700;'
        f'padding:.2em .5em;border-radius:3px;text-transform:uppercase;letter-spacing:.05em">'
        f'{_escape(level)}</span>'
    )


def _timeline_row(alert: Alert) -> str:
    color = LEVEL_CSS.get(alert.level, "#aaa")
    ts = alert.fired_at.strftime("%H:%M:%S")
    tech_info = mitre_db.lookup(alert.mitre_technique)
    tech_url = tech_info.get("url", "#")

    evidence_rows = ""
    for ev in alert.evidence[:5]:
        fields = {k: v for k, v in ev.raw.items()
                  if k not in ("timestamp", "event_type", "message") and v}
        field_str = "  ".join(
            f'<span style="color:#555">{_escape(k)}=</span>'
            f'<span style="color:#777">{_escape(str(v))}</span>'
            for k, v in list(fields.items())[:5]
        )
        ev_ts = ev.timestamp.strftime("%H:%M:%S")
        evidence_rows += (
            f'<div style="font-family:monospace;font-size:.74rem;padding:.15rem 0;'
            f'border-left:2px solid #1e1e1e;padding-left:.6rem;margin-top:.2rem">'
            f'<span style="color:#444">{ev_ts}</span> '
            f'<span style="color:#555">{_escape(ev.event_type)}</span> '
            f'{field_str}</div>'
        )
    if len(alert.evidence) > 5:
        evidence_rows += (
            f'<div style="color:#444;font-size:.72rem;padding-left:.6rem">'
            f'… {len(alert.evidence) - 5} more events</div>'
        )

    return f"""
<div class="alert-row" style="border-left:3px solid {color}">
  <div class="alert-header">
    <span style="color:#444;font-size:.75rem;font-family:monospace;margin-right:.8rem">{ts}</span>
    {_badge(alert.level)}
    <span class="alert-title">{_escape(alert.rule_title)}</span>
    <span style="color:#333;font-size:.75rem;margin-left:auto">
      <a href="{tech_url}" style="color:#555;text-decoration:none" target="_blank">
        {_escape(alert.mitre_technique)}
      </a>
    </span>
  </div>
  <div style="color:#666;font-size:.8rem;margin:.3rem 0">{_escape(alert.summary)}</div>
  {evidence_rows}
</div>"""


def _tactic_breakdown(alerts: List[Alert]) -> str:
    by_tactic: dict = {}
    for a in alerts:
        tactic = a.mitre_tactic or "Unknown"
        by_tactic.setdefault(tactic, []).append(a)

    cells = ""
    for tactic in TACTIC_ORDER:
        if tactic not in by_tactic:
            continue
        count = len(by_tactic[tactic])
        max_level = min(by_tactic[tactic], key=lambda a: a.level_rank).level
        color = LEVEL_CSS.get(max_level, "#888")
        cells += (
            f'<div style="background:#111;border:1px solid #1e1e1e;border-top:2px solid {color};'
            f'border-radius:4px;padding:.6rem .9rem;text-align:center">'
            f'<div style="color:{color};font-size:1.3rem;font-weight:700">{count}</div>'
            f'<div style="color:#666;font-size:.68rem;text-transform:uppercase;margin-top:.2rem">'
            f'{_escape(tactic)}</div></div>'
        )
    return f'<div style="display:flex;gap:.75rem;flex-wrap:wrap;margin:1.5rem 0">{cells}</div>'


def generate_report(
    log_path: str,
    events: List[LogEvent],
    alerts: List[Alert],
    output_path: str,
) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts: dict = {}
    for a in alerts:
        counts[a.level] = counts.get(a.level, 0) + 1

    stat_html = ""
    for level in ["critical", "high", "medium", "low", "informational"]:
        if level in counts:
            color = LEVEL_CSS[level]
            stat_html += (
                f'<div class="stat"><span style="color:{color};font-size:1.8rem;font-weight:700">'
                f'{counts[level]}</span><br>'
                f'<span style="color:#888;font-size:.72rem;text-transform:uppercase">{level}</span></div>'
            )

    timeline_html = "\n".join(_timeline_row(a) for a in alerts) if alerts else (
        '<div style="color:#555;padding:2rem 0">No alerts fired.</div>'
    )

    unique_techniques = sorted({a.mitre_technique for a in alerts})
    tech_pills = "".join(
        f'<a href="{mitre_db.lookup(t).get("url","#")}" target="_blank" '
        f'style="display:inline-block;background:#111;border:1px solid #1e1e1e;'
        f'border-radius:4px;padding:.25rem .6rem;font-size:.74rem;color:#7c3aed;'
        f'text-decoration:none;margin:.2rem">{_escape(t)} — {_escape(mitre_db.lookup(t).get("name",""))}</a>'
        for t in unique_techniques
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus Detection Report</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:#0d0d0d; color:#e0e0e0; font-family:'Segoe UI',system-ui,sans-serif; padding:2rem; max-width:1000px; margin:0 auto; }}
  .header {{ border-bottom:1px solid #222; padding-bottom:1.5rem; margin-bottom:2rem; }}
  .header h1 {{ font-size:1.6rem; font-weight:700; color:#fff; }}
  .header h1 span {{ color:#7c3aed; }}
  .meta {{ color:#555; font-size:.85rem; margin-top:.4rem; }}
  .stats {{ display:flex; gap:1.5rem; margin:1.5rem 0; flex-wrap:wrap; }}
  .stat {{ text-align:center; background:#111; border:1px solid #1e1e1e; border-radius:8px; padding:.8rem 1.2rem; }}
  .section-label {{ color:#555; font-size:.68rem; text-transform:uppercase; letter-spacing:.1em; margin:2rem 0 .8rem; }}
  .alert-row {{ background:#111; border-radius:6px; padding:1rem 1.1rem; margin-bottom:.6rem; }}
  .alert-header {{ display:flex; align-items:center; gap:.7rem; margin-bottom:.4rem; flex-wrap:wrap; }}
  .alert-title {{ font-weight:600; color:#f0f0f0; font-size:.9rem; }}
  footer {{ margin-top:3rem; color:#333; font-size:.75rem; border-top:1px solid #1a1a1a; padding-top:1rem; }}
</style>
</head>
<body>
<div class="header">
  <h1><span>Argus</span> Detection Report</h1>
  <div class="meta">
    Log: {_escape(log_path)} &nbsp;|&nbsp;
    {now} &nbsp;|&nbsp;
    {len(events)} events processed &nbsp;|&nbsp;
    {len(alerts)} alert{"s" if len(alerts) != 1 else ""} fired
  </div>
</div>

<div class="stats">
  {stat_html}
  <div class="stat">
    <span style="color:#e0e0e0;font-size:1.8rem;font-weight:700">{len(alerts)}</span><br>
    <span style="color:#888;font-size:.72rem;text-transform:uppercase">Total</span>
  </div>
  <div class="stat">
    <span style="color:#e0e0e0;font-size:1.8rem;font-weight:700">{len(events)}</span><br>
    <span style="color:#888;font-size:.72rem;text-transform:uppercase">Events</span>
  </div>
</div>

<div class="section-label">ATT&CK Coverage</div>
{_tactic_breakdown(alerts)}

<div class="section-label">Techniques Detected</div>
<div style="margin-bottom:1.5rem">{tech_pills if tech_pills else '<span style="color:#555">None</span>'}</div>

<div class="section-label">Alert Timeline</div>
{timeline_html}

<footer>
  Generated by <strong>Argus</strong> &nbsp;|&nbsp;
  MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation &nbsp;|&nbsp;
  For authorised security analysis and educational use only.
</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
