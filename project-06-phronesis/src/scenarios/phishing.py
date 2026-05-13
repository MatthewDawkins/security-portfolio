from typing import Dict

from src.models import ActionRecommendation, Equilibrium
from src.scenarios.base import BaseScenario, _dominant_action


class PhishingTargeting(BaseScenario):
    name = "phishing"
    description = "Optimal security awareness training allocation vs. a targeting adversary"
    params_help = {
        "exec_breach_cost":    (80,  "Cost of a successful executive/privileged account compromise"),
        "staff_breach_cost":   (40,  "Cost of a successful general-staff compromise"),
        "training_effectiveness":(20, "Value of security training (breach prevented minus training cost)"),
    }

    def build_game(self, params: Dict) -> Dict:
        ebc = params["exec_breach_cost"]
        sbc = params["staff_breach_cost"]
        te  = params["training_effectiveness"]

        # Payoff matrix (Defender, Attacker):
        #   Defender allocates awareness training budget to executives or general staff.
        #   Attacker selects which group to target with a phishing campaign.
        #   Match  → trained group targeted: attack prevented, defender captures training value
        #   Miss   → untrained group targeted: breach occurs
        return {
            "players": ["Defender", "Attacker"],
            "actions": {
                "Defender": ["Train-Exec",  "Train-Staff"],
                "Attacker": ["Phish-Exec",  "Phish-Staff"],
            },
            "payoffs": {
                "Train-Exec,Phish-Exec":   [ te,   -te],
                "Train-Exec,Phish-Staff":  [-sbc,   sbc],
                "Train-Staff,Phish-Exec":  [-ebc,   ebc],
                "Train-Staff,Phish-Staff": [ te,   -te],
            },
        }

    def interpret(self, eq: Equilibrium, params: Dict) -> tuple:
        ebc = params["exec_breach_cost"]
        sbc = params["staff_breach_cost"]
        te  = params["training_effectiveness"]

        d_strat = next(s for s in eq.strategies if s.player == "Defender")
        a_strat = next(s for s in eq.strategies if s.player == "Attacker")

        p_train_exec  = d_strat.probabilities.get("Train-Exec",  0)
        p_train_staff = d_strat.probabilities.get("Train-Staff", 0)
        p_phish_exec  = a_strat.probabilities.get("Phish-Exec",  0)
        p_phish_staff = a_strat.probabilities.get("Phish-Staff", 0)

        defender_rec = ActionRecommendation(
            player="Defender",
            recommended_action="Train-Exec",
            probabilities=d_strat.probabilities,
            rationale=(
                f"Allocate {p_train_exec * 100:.1f}% of your security awareness budget to "
                f"executives and privileged users, and {p_train_staff * 100:.1f}% to general "
                f"staff. This split is proportional to the breach cost asymmetry: "
                f"executive compromise ({ebc} units) vs. staff compromise ({sbc} units). "
                f"A pure executive-only training strategy is predictable and leaves staff "
                f"systematically undertrained — the Nash mixed strategy eliminates this "
                f"exploitable pattern."
            ),
        )

        attacker_profile = ActionRecommendation(
            player="Attacker",
            recommended_action=_dominant_action(a_strat.probabilities),
            probabilities=a_strat.probabilities,
            rationale=(
                f"Despite executives representing {ebc / sbc:.1f}x the breach value of "
                f"staff, a rational attacker targets executives only {p_phish_exec * 100:.1f}% "
                f"of the time. The higher defensive training concentration on executives "
                f"({p_train_exec * 100:.1f}%) suppresses the incentive to target them. "
                f"The attacker predominantly ({p_phish_staff * 100:.1f}%) targets staff, "
                f"where training coverage is thinner."
            ),
        )

        interpretation = (
            f"The phishing targeting game produces a result that challenges the 'train your "
            f"executives first' heuristic. While executives are {ebc / sbc:.1f}x more valuable "
            f"targets, the Nash equilibrium has attackers phishing them only "
            f"{p_phish_exec * 100:.1f}% of the time — because defenders rationally skew "
            f"{p_train_exec * 100:.1f}% of their training budget toward executives. "
            f"The practical recommendation is to train executives more but not exclusively: "
            f"a {p_train_exec * 100:.0f}/{p_train_staff * 100:.0f} split is the unexploitable "
            f"allocation. An organisation that trains only executives signals to attackers "
            f"that staff are soft targets; an organisation that splits evenly signals that "
            f"executives are under-protected relative to their value. The equilibrium split "
            f"({p_train_exec * 100:.1f}% / {p_train_staff * 100:.1f}%) is the unique "
            f"allocation where neither group is a systematically preferred target. "
            f"At equilibrium, the expected loss per campaign is "
            f"{abs(d_strat.expected_payoff):.1f} units."
        )

        return defender_rec, attacker_profile, interpretation
