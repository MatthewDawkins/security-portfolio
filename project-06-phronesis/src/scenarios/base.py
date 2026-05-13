from abc import ABC, abstractmethod
from typing import Dict

from src.gto_client import solve
from src.models import (
    ActionRecommendation,
    Equilibrium,
    PlayerStrategy,
    ScenarioResult,
)


def _parse_equilibrium(raw: Dict) -> Equilibrium:
    eq = raw["equilibria"][0]
    strategies = []
    for player, probs in eq["strategy"].items():
        strategies.append(PlayerStrategy(
            player=player,
            probabilities=probs,
            expected_payoff=eq["expected_payoffs"].get(player, 0.0),
        ))
    return Equilibrium(
        strategies=strategies,
        solver=raw.get("solver", "support-enumeration"),
        duration_ms=raw.get("duration-ms", 0),
    )


def _dominant_action(probs: Dict[str, float]) -> str:
    return max(probs, key=probs.__getitem__)


class BaseScenario(ABC):
    name: str = ""
    description: str = ""
    params_help: Dict[str, tuple] = {}  # param -> (default, description)

    @abstractmethod
    def build_game(self, params: Dict) -> Dict:
        """Construct the GTO game definition dict from user-supplied parameters."""
        ...

    @abstractmethod
    def interpret(self, equilibrium: Equilibrium, params: Dict) -> tuple:
        """
        Return (defender_rec, attacker_profile, interpretation_text).

        defender_rec      : ActionRecommendation for the defender player
        attacker_profile  : ActionRecommendation describing attacker equilibrium
        interpretation    : Multi-sentence strategic analysis string
        """
        ...

    def default_params(self) -> Dict:
        return {k: v[0] for k, v in self.params_help.items()}

    def run(self, params: Dict, api_key: str) -> ScenarioResult:
        merged = {**self.default_params(), **params}
        game = self.build_game(merged)
        raw = solve(game, api_key)
        eq = _parse_equilibrium(raw)
        defender_rec, attacker_profile, interpretation = self.interpret(eq, merged)
        return ScenarioResult(
            scenario_name=self.name,
            scenario_description=self.description,
            params=merged,
            game=game,
            equilibrium=eq,
            defender_recommendation=defender_rec,
            attacker_profile=attacker_profile,
            interpretation=interpretation,
            raw_response=raw,
        )
