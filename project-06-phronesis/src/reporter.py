from datetime import datetime, timezone
from typing import List

from src.models import ScenarioResult

SEVERITY_CSS = {
    "Defender": "#7c3aed",
    "Attacker": "#ff8800",
}


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def _pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def _bar(prob: float, color: str) -> str:
    width = max(2, int(prob * 180))
    return (
        f'<div style="display:inline-block;height:10px;width:{width}px;'
        f'background:{color};border-radius:2px;margin-right:6px;vertical-align:middle"></div>'
    )


def _strategy_table(strategies, player_colors) -> str:
    rows = ""
    for strat in strategies:
        color = player_colors.get(strat.player, "#aaa")
        rows += f'<tr><td style="color:{color};font-weight:600;padding-right:1.5rem">{_escape(strat.player)}</td>'
        for action, prob in sorted(strat.probabilities.items(), key=lambda x: -x[1]):
            rows += (
                f'<td style="padding:.3rem .8rem .3rem 0">'
                f'{_bar(prob, color)}'
                f'<span style="color:#e0e0e0;font-size:.85rem">{_escape(action)}</span>'
                f'<span style="color:#666;font-size:.78rem;margin-left:.4rem">{_pct(prob)}</span>'
                f'</td>'
            )
        rows += (
            f'<td style="color:#555;font-size:.78rem;padding-left:1rem">'
            f'E[payoff] = {strat.expected_payoff:.2f}</td></tr>'
        )
    return f'<table style="border-collapse:collapse;margin:.5rem 0">{rows}</table>'


def _payoff_matrix(game: dict) -> str:
    players = game["players"]
    payoffs = game["payoffs"]
    p1_actions = game["actions"][players[0]]
    p2_actions = game["actions"][players[1]]

    header = f'<th></th>' + "".join(
        f'<th style="color:#7c3aed;font-size:.78rem;padding:.3rem .6rem">{_escape(a)}</th>'
        for a in p2_actions
    )
    rows = ""
    for a1 in p1_actions:
        row = f'<td style="color:#ff8800;font-size:.78rem;padding:.3rem .6rem;font-weight:600">{_escape(a1)}</td>'
        for a2 in p2_actions:
            key = f"{a1},{a2}"
            vals = payoffs.get(key, [0, 0])
            d_color = "#4ade80" if vals[0] >= 0 else "#ff6666"
            a_color = "#4ade80" if vals[1] >= 0 else "#ff6666"
            row += (
                f'<td style="text-align:center;padding:.3rem .8rem;border:1px solid #1e1e1e;font-size:.8rem">'
                f'<span style="color:{d_color}">{vals[0]}</span>'
                f'<span style="color:#444">, </span>'
                f'<span style="color:{a_color}">{vals[1]}</span>'
                f'</td>'
            )
        rows += f"<tr>{row}</tr>"

    return (
        f'<div style="margin:.5rem 0">'
        f'<div style="font-size:.7rem;color:#555;margin-bottom:.4rem">'
        f'<span style="color:#ff8800">{_escape(players[0])}</span> (row) vs '
        f'<span style="color:#7c3aed">{_escape(players[1])}</span> (col) — '
        f'values shown as (defender, attacker)</div>'
        f'<table style="border-collapse:collapse">'
        f'<tr>{header}</tr>{rows}'
        f'</table></div>'
    )


def _scenario_section(result: ScenarioResult, idx: int) -> str:
    player_colors = {"Defender": "#7c3aed", "Attacker": "#ff8800"}
    param_items = "".join(
        f'<span style="color:#555;font-size:.78rem;margin-right:1rem">'
        f'{_escape(k)}: <span style="color:#888">{v}</span></span>'
        for k, v in result.params.items()
    )

    return f"""
<div class="scenario" id="scenario-{idx}">
  <div class="scenario-header">
    <span class="scenario-num">{idx}</span>
    <div>
      <div class="scenario-title">{_escape(result.scenario_name.upper())} — {_escape(result.scenario_description)}</div>
      <div style="margin-top:.3rem">{param_items}</div>
    </div>
  </div>

  <div class="section-label">Payoff Matrix</div>
  {_payoff_matrix(result.game)}

  <div class="section-label" style="margin-top:1.2rem">Nash Equilibrium  <span style="color:#444;font-size:.7rem;font-weight:400">({_escape(result.equilibrium.solver)}, {result.equilibrium.duration_ms}ms)</span></div>
  {_strategy_table(result.equilibrium.strategies, player_colors)}

  <div class="section-label" style="margin-top:1.2rem">Defender Recommendation</div>
  <div class="rec-box defender">
    <div class="rec-action">
      Recommended: <span style="color:#7c3aed">{_escape(result.defender_recommendation.recommended_action)}</span>
    </div>
    <div class="rec-rationale">{_escape(result.defender_recommendation.rationale)}</div>
  </div>

  <div class="section-label" style="margin-top:1rem">Attacker Profile</div>
  <div class="rec-box attacker">
    <div class="rec-action">
      Expected play: <span style="color:#ff8800">{_escape(result.attacker_profile.recommended_action)}</span>
    </div>
    <div class="rec-rationale">{_escape(result.attacker_profile.rationale)}</div>
  </div>

  <div class="section-label" style="margin-top:1rem">Strategic Analysis</div>
  <div class="interpretation">{_escape(result.interpretation)}</div>
</div>"""


def generate_report(results: List[ScenarioResult], output_path: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scenarios_html = "\n".join(_scenario_section(r, i + 1) for i, r in enumerate(results))
    scenario_count = len(results)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phronesis — Adversary Simulation Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d0d0d; color: #e0e0e0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; max-width: 960px; margin: 0 auto; }}
  .header {{ border-bottom: 1px solid #222; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.6rem; font-weight: 700; color: #fff; }}
  .header h1 span {{ color: #7c3aed; }}
  .meta {{ color: #555; font-size: .85rem; margin-top: .4rem; }}
  .tagline {{ color: #444; font-size: .82rem; margin-top: .6rem; font-style: italic; }}
  .summary {{ display: flex; gap: 1.5rem; margin: 2rem 0; flex-wrap: wrap; }}
  .stat {{ text-align: center; background: #111; border: 1px solid #1e1e1e; border-radius: 8px; padding: .8rem 1.2rem; }}
  .scenario {{ background: #111; border-radius: 8px; padding: 1.4rem; margin-bottom: 1.5rem; border-left: 3px solid #7c3aed; }}
  .scenario-header {{ display: flex; align-items: flex-start; gap: 1rem; margin-bottom: 1rem; }}
  .scenario-num {{ background: #7c3aed; color: #fff; font-size: .75rem; font-weight: 700; width: 22px; height: 22px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 2px; }}
  .scenario-title {{ font-weight: 600; color: #f0f0f0; font-size: .95rem; }}
  .section-label {{ color: #555; font-size: .68rem; text-transform: uppercase; letter-spacing: .1em; margin-top: 1rem; margin-bottom: .4rem; }}
  .rec-box {{ background: #0d0d0d; border-radius: 6px; padding: .9rem 1rem; margin-top: .3rem; }}
  .rec-box.defender {{ border-left: 2px solid #7c3aed; }}
  .rec-box.attacker {{ border-left: 2px solid #ff8800; }}
  .rec-action {{ font-size: .85rem; font-weight: 600; color: #ccc; margin-bottom: .4rem; }}
  .rec-rationale {{ font-size: .83rem; color: #888; line-height: 1.6; }}
  .interpretation {{ font-size: .84rem; color: #999; line-height: 1.7; background: #0d0d0d; border-radius: 6px; padding: .9rem 1rem; border-left: 2px solid #333; }}
  footer {{ margin-top: 3rem; color: #333; font-size: .75rem; border-top: 1px solid #1a1a1a; padding-top: 1rem; }}
  footer a {{ color: #555; }}
</style>
</head>
<body>
<div class="header">
  <h1><span>Phronesis</span> — Adversary Simulation Report</h1>
  <div class="meta">{now} &nbsp;|&nbsp; {scenario_count} scenario{"s" if scenario_count != 1 else ""} analysed &nbsp;|&nbsp; Powered by <a href="https://mieza.ai" style="color:#7c3aed;text-decoration:none">Mieza GTO</a></div>
  <div class="tagline">Nash equilibrium strategies for defender resource allocation — computed via Counterfactual Regret Minimization</div>
</div>

<div class="summary">
  <div class="stat">
    <span style="color:#7c3aed;font-size:1.8rem;font-weight:700">{scenario_count}</span><br>
    <span style="color:#888;font-size:.75rem;text-transform:uppercase">Scenarios</span>
  </div>
  <div class="stat">
    <span style="color:#e0e0e0;font-size:1.8rem;font-weight:700">{sum(len(r.equilibrium.strategies[0].probabilities) for r in results)}</span><br>
    <span style="color:#888;font-size:.75rem;text-transform:uppercase">Actions Modelled</span>
  </div>
  <div class="stat">
    <span style="color:#4ade80;font-size:1.8rem;font-weight:700">{sum(1 for r in results if len(r.equilibrium.strategies[0].probabilities) > 1)}</span><br>
    <span style="color:#888;font-size:.75rem;text-transform:uppercase">Mixed Equilibria</span>
  </div>
</div>

{scenarios_html}

<footer>
  Generated by <strong>Phronesis</strong> &nbsp;|&nbsp;
  Solver: <a href="https://mieza.ai">Mieza GTO — support-enumeration Nash solver</a> &nbsp;|&nbsp;
  For authorised security analysis and educational use only.
</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
