from typing import Dict

from src.models import ActionRecommendation, Equilibrium
from src.scenarios.base import BaseScenario, _dominant_action


class HoneypotPlacement(BaseScenario):
    name = "honeypot"
    description = "Optimal honeypot allocation across assets of asymmetric value"
    params_help = {
        "high_value_asset_loss":  (100, "Breach loss if high-value system is compromised"),
        "low_value_asset_loss":   (40,  "Breach loss if low-value system is compromised"),
        "honeypot_detection_gain":(20,  "Intelligence / deterrence value of catching attacker in honeypot"),
    }

    def build_game(self, params: Dict) -> Dict:
        hvl = params["high_value_asset_loss"]
        lvl = params["low_value_asset_loss"]
        hdg = params["honeypot_detection_gain"]

        # Payoff matrix (Defender, Attacker):
        #   Defender places honeypot on A (high-value) or B (low-value)
        #   Attacker targets A or B
        #   Match  → attacker caught in honeypot: defender gains intel, attacker penalised
        #   Miss   → attacker breaches unprotected system: defender suffers loss, attacker gains
        return {
            "players": ["Defender", "Attacker"],
            "actions": {
                "Defender": ["Honeypot-A", "Honeypot-B"],
                "Attacker": ["Target-A",   "Target-B"],
            },
            "payoffs": {
                "Honeypot-A,Target-A": [ hdg,  -hdg],
                "Honeypot-A,Target-B": [-lvl,   lvl],
                "Honeypot-B,Target-A": [-hvl,   hvl],
                "Honeypot-B,Target-B": [ hdg,  -hdg],
            },
        }

    def interpret(self, eq: Equilibrium, params: Dict) -> tuple:
        hvl = params["high_value_asset_loss"]
        lvl = params["low_value_asset_loss"]
        hdg = params["honeypot_detection_gain"]

        d_strat = next(s for s in eq.strategies if s.player == "Defender")
        a_strat = next(s for s in eq.strategies if s.player == "Attacker")

        p_hp_a    = d_strat.probabilities.get("Honeypot-A", 0)
        p_hp_b    = d_strat.probabilities.get("Honeypot-B", 0)
        p_tgt_a   = a_strat.probabilities.get("Target-A",   0)
        p_tgt_b   = a_strat.probabilities.get("Target-B",   0)

        defender_rec = ActionRecommendation(
            player="Defender",
            recommended_action="Honeypot-A",
            probabilities=d_strat.probabilities,
            rationale=(
                f"Deploy your honeypot on the high-value system {p_hp_a * 100:.1f}% of the time "
                f"and on the low-value system {p_hp_b * 100:.1f}% of the time. This mixed "
                f"deployment is derived from the asymmetry between breach losses "
                f"({hvl} vs {lvl}) and detection gain ({hdg}). A deterministic "
                f"honeypot always on the high-value asset is trivially circumvented — "
                f"randomisation forces the attacker to account for both possibilities."
            ),
        )

        attacker_profile = ActionRecommendation(
            player="Attacker",
            recommended_action=_dominant_action(a_strat.probabilities),
            probabilities=a_strat.probabilities,
            rationale=(
                f"A rational adversary targets the high-value system only {p_tgt_a * 100:.1f}% "
                f"of the time — despite its higher value — because defenders concentrate "
                f"honeypot coverage there. The low-value system is targeted "
                f"{p_tgt_b * 100:.1f}% of the time as the relatively safer option."
            ),
        )

        interpretation = (
            f"This inspection-game result is counterintuitive: the Nash equilibrium "
            f"has the attacker targeting your high-value system only {p_tgt_a * 100:.1f}% "
            f"of the time, even though it is worth {hvl / lvl:.1f}x more. The reason is "
            f"that defenders rationally concentrate protection ({p_hp_a * 100:.1f}% honeypot "
            f"coverage) on the high-value asset, which suppresses attacker incentive to "
            f"target it. "
            f"The practical implication is that a static, predictable honeypot on your "
            f"most valuable system is exploitable: a sophisticated attacker simply avoids "
            f"it. Randomised deployment — {p_hp_a * 100:.1f}% / {p_hp_b * 100:.1f}% split — "
            f"makes the attacker's decision genuinely uncertain, achieving maximum deterrence "
            f"per honeypot. The defender's expected loss at equilibrium is "
            f"{abs(d_strat.expected_payoff):.1f} units, which is the minimum achievable "
            f"given the asset value asymmetry."
        )

        return defender_rec, attacker_profile, interpretation
