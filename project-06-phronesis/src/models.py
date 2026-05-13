from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PlayerStrategy:
    player: str
    probabilities: Dict[str, float]   # action -> probability
    expected_payoff: float


@dataclass
class Equilibrium:
    strategies: List[PlayerStrategy]
    solver: str
    duration_ms: int


@dataclass
class ActionRecommendation:
    """A single player's strategic recommendation derived from the Nash equilibrium."""
    player: str
    recommended_action: str           # highest-probability action
    probabilities: Dict[str, float]   # full mixed strategy
    rationale: str                    # plain-English explanation


@dataclass
class ScenarioResult:
    scenario_name: str
    scenario_description: str
    params: Dict
    game: Dict                        # raw game definition sent to solver
    equilibrium: Equilibrium
    defender_recommendation: ActionRecommendation
    attacker_profile: ActionRecommendation
    interpretation: str               # multi-sentence strategic analysis
    raw_response: Dict
