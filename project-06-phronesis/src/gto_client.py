import requests
from typing import Dict

GTO_SOLVE_URL = "https://mieza.ai/v1/nf-solve"
TIMEOUT = 30


def solve(game: Dict, api_key: str) -> Dict:
    """
    Call the Mieza GTO normal-form solver.

    Sends the game definition to the ephemeral solve endpoint (no persistence).
    Requires a Bearer API key to bypass CSRF protection.

    Returns the raw JSON response as a dict:
      {
        "game": {"players": [...]},
        "solver": "support-enumeration",
        "equilibria": [
          {
            "strategy": {
              "Player1": {"Action1": 0.6, "Action2": 0.4},
              "Player2": {"ActionA": 0.5, "ActionB": 0.5}
            },
            "expected_payoffs": {"Player1": -10.0, "Player2": 5.0}
          }
        ],
        "duration-ms": 3
      }
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    resp = requests.post(GTO_SOLVE_URL, json={"game": game}, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()
