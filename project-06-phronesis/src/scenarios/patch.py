from typing import Dict

from src.models import ActionRecommendation, Equilibrium
from src.scenarios.base import BaseScenario, _dominant_action


class PatchManagement(BaseScenario):
    name = "patch"
    description = "Optimal patch cadence vs. an adaptive exploit-timing adversary"
    params_help = {
        "breach_cost":  (100, "Estimated cost of a successful breach (arbitrary units)"),
        "patch_cost":   (20,  "Cost to the defender of applying a patch"),
        "exploit_gain": (80,  "Value an attacker extracts from a successful exploit"),
        "attack_cost":  (15,  "Cost the attacker incurs to attempt an exploit"),
    }

    def build_game(self, params: Dict) -> Dict:
        bc  = params["breach_cost"]
        pc  = params["patch_cost"]
        eg  = params["exploit_gain"]
        ac  = params["attack_cost"]

        # Payoff matrix (Defender, Attacker):
        #   Patch  + Exploit  → Defender pays patch cost; attacker fails and wastes attack cost
        #   Patch  + Wait     → Defender pays patch cost; attacker saves effort
        #   Defer  + Exploit  → Defender suffers breach (saves patch cost); attacker succeeds
        #   Defer  + Wait     → Both neutral; no action taken
        return {
            "players": ["Defender", "Attacker"],
            "actions": {
                "Defender": ["Patch", "Defer"],
                "Attacker": ["Exploit", "Wait"],
            },
            "payoffs": {
                "Patch,Exploit": [-pc,      -ac],
                "Patch,Wait":    [-pc,       0],
                "Defer,Exploit": [-bc,       eg],
                "Defer,Wait":    [0,          0],
            },
        }

    def interpret(self, eq: Equilibrium, params: Dict) -> tuple:
        bc = params["breach_cost"]
        pc = params["patch_cost"]

        d_strat = next(s for s in eq.strategies if s.player == "Defender")
        a_strat = next(s for s in eq.strategies if s.player == "Attacker")

        p_patch   = d_strat.probabilities.get("Patch",   0)
        p_exploit = a_strat.probabilities.get("Exploit", 0)
        p_wait    = a_strat.probabilities.get("Wait",    0)

        expected_loss_if_defer = bc * p_exploit
        expected_loss_if_patch = pc

        defender_rec = ActionRecommendation(
            player="Defender",
            recommended_action="Patch",
            probabilities=d_strat.probabilities,
            rationale=(
                f"Apply patches on {p_patch * 100:.1f}% of disclosed vulnerabilities "
                f"within your response window. Deferring exposes you to an expected loss of "
                f"{expected_loss_if_defer:.1f} units per vulnerability "
                f"(breach cost {bc} × attacker exploit probability {p_exploit:.0%}), "
                f"which exceeds the patch cost of {pc} only when p_exploit > {pc/bc:.0%}. "
                f"At Nash equilibrium the attacker exploits exactly often enough to make "
                f"you indifferent — so patching at this rate is unexploitable."
            ),
        )

        attacker_profile = ActionRecommendation(
            player="Attacker",
            recommended_action=_dominant_action(a_strat.probabilities),
            probabilities=a_strat.probabilities,
            rationale=(
                f"A rational adversary exploits {p_exploit * 100:.1f}% of unpatched windows "
                f"and waits {p_wait * 100:.1f}% of the time. Exploit attempts beyond this "
                f"rate are suboptimal because high patch probability reduces expected payoff "
                f"below attack cost."
            ),
        )

        interpretation = (
            f"The Nash equilibrium for this patch-management game prescribes that "
            f"defenders patch {p_patch * 100:.1f}% of critical disclosures — not 100%, "
            f"because patching every vulnerability immediately costs more than the expected "
            f"breach loss when the attacker exploits only {p_exploit * 100:.1f}% of exposure "
            f"windows. Concretely, the break-even patch rate is {pc / bc:.0%}: below that "
            f"threshold, deferral is rational; above it, patching wins. "
            f"The attacker's equilibrium strategy reveals that aggressive exploit campaigns "
            f"are self-defeating — mounting too many attacks drives defenders to patch more "
            f"frequently, erasing the attacker's advantage. At the equilibrium, the "
            f"defender's expected loss per vulnerability is {abs(d_strat.expected_payoff):.1f} "
            f"units regardless of which action they take, because the attacker has calibrated "
            f"exploit frequency to make the defender indifferent."
        )

        return defender_rec, attacker_profile, interpretation
