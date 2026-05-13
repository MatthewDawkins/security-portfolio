from typing import Dict

from src.models import ActionRecommendation, Equilibrium
from src.scenarios.base import BaseScenario, _dominant_action


class IDSSensitivity(BaseScenario):
    name = "ids"
    description = "Optimal IDS sensitivity tuning against stealthy vs. noisy attackers"
    params_help = {
        "breach_cost":       (80, "Cost of a successful breach (missed detection)"),
        "false_positive_cost":(10, "Analyst overhead cost per period from high-sensitivity IDS"),
        "stealthy_attack_cost":(20, "Additional cost the attacker incurs to mount a stealthy attack"),
        "noisy_attack_cost":  (5,  "Cost of a cheap, noisy attack attempt"),
        "stealthy_breach_gain":(60, "Attacker value from a successful stealthy breach"),
    }

    def build_game(self, params: Dict) -> Dict:
        bc  = params["breach_cost"]
        fpc = params["false_positive_cost"]
        sac = params["stealthy_attack_cost"]
        nac = params["noisy_attack_cost"]
        sbg = params["stealthy_breach_gain"]

        # Payoff matrix (Defender, Attacker):
        #   High-IDS catches both noisy and stealthy attacks — but incurs FP overhead.
        #   Low-IDS catches noisy attacks (they are obvious) but misses stealthy ones.
        #
        #   High-IDS + Noisy    → caught, defender pays FP cost; attacker fails
        #   High-IDS + Stealthy → caught, defender pays FP cost; attacker fails (costly attempt)
        #   Low-IDS  + Noisy    → caught (noisy is obvious even to low IDS); no FP overhead
        #   Low-IDS  + Stealthy → BREACH; defender suffers full breach cost
        return {
            "players": ["Defender", "Attacker"],
            "actions": {
                "Defender": ["High-IDS", "Low-IDS"],
                "Attacker": ["Noisy",    "Stealthy"],
            },
            "payoffs": {
                "High-IDS,Noisy":    [-fpc,       -nac],
                "High-IDS,Stealthy": [-fpc,       -sac],
                "Low-IDS,Noisy":     [0,           -nac],
                "Low-IDS,Stealthy":  [-bc,          sbg],
            },
        }

    def interpret(self, eq: Equilibrium, params: Dict) -> tuple:
        bc  = params["breach_cost"]
        fpc = params["false_positive_cost"]
        sac = params["stealthy_attack_cost"]

        d_strat = next(s for s in eq.strategies if s.player == "Defender")
        a_strat = next(s for s in eq.strategies if s.player == "Attacker")

        p_high    = d_strat.probabilities.get("High-IDS", 0)
        p_low     = d_strat.probabilities.get("Low-IDS",  0)
        p_noisy   = a_strat.probabilities.get("Noisy",    0)
        p_stealthy= a_strat.probabilities.get("Stealthy", 0)

        break_even = fpc / bc

        defender_rec = ActionRecommendation(
            player="Defender",
            recommended_action="High-IDS",
            probabilities=d_strat.probabilities,
            rationale=(
                f"Run high-sensitivity IDS {p_high * 100:.1f}% of the time. "
                f"The break-even point is when stealthy breach probability equals "
                f"{break_even:.0%} (FP cost {fpc} / breach cost {bc}). "
                f"At equilibrium, attackers use stealthy techniques only {p_stealthy * 100:.1f}% "
                f"of the time — the high-IDS rate makes stealthy attacks costly enough to "
                f"suppress their use. Consider correlating high-sensitivity periods to "
                f"elevated threat intelligence cycles."
            ),
        )

        attacker_profile = ActionRecommendation(
            player="Attacker",
            recommended_action=_dominant_action(a_strat.probabilities),
            probabilities=a_strat.probabilities,
            rationale=(
                f"A rational attacker favours noisy, cheap attacks {p_noisy * 100:.1f}% of "
                f"the time because the high probability of elevated IDS ({p_high * 100:.1f}%) "
                f"makes the extra cost of stealthy techniques ({sac} units) unjustifiable. "
                f"Stealthy attacks are reserved for the {p_stealthy * 100:.1f}% of periods "
                f"when low-IDS is expected."
            ),
        )

        interpretation = (
            f"The equilibrium prescribes running high-sensitivity IDS {p_high * 100:.1f}% "
            f"of the time — not always, because the false-positive analyst burden ({fpc} units) "
            f"is a real cost, and permanent high sensitivity is wasteful when attackers adapt. "
            f"The key insight is the feedback loop: the higher the IDS rate, the less "
            f"attractive stealthy attacks become, because the extra cost ({sac} units) yields "
            f"no benefit if likely to be caught anyway. At {p_high * 100:.1f}% high-IDS, "
            f"attackers respond by using stealthy techniques only {p_stealthy * 100:.1f}% of "
            f"the time — which is exactly the rate that makes the defender indifferent between "
            f"sensitivity levels. A defender who runs high-IDS less than {p_high * 100:.1f}% "
            f"of the time creates an exploitable gap: attackers will increase stealthy attack "
            f"frequency, raising breach probability faster than the FP cost savings justify."
        )

        return defender_rec, attacker_profile, interpretation
