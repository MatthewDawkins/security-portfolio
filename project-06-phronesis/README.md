# Phronesis — Adversary Simulation via Nash Equilibrium

> A Python CLI that models attacker/defender security decisions as two-player normal-form games, solves them for Nash equilibria via the [Mieza GTO engine](https://mieza.ai), and outputs actionable defense recommendations with a self-contained HTML report.

---

## What It Does

Security decisions — how often to patch, where to place honeypots, how to tune IDS sensitivity, how to allocate training budgets — are fundamentally adversarial: an attacker adapts to the defender's strategy, and the defender must account for that adaptation. Standard heuristics (always patch immediately, always train executives first) are exploitable because they are predictable.

Phronesis frames each decision as a two-player game and computes the **Nash equilibrium**: the unique mixed strategy where neither side can improve their outcome by changing behavior unilaterally. The result is an *unexploitable* defense posture — not the best case assumption, but the optimal strategy against a rational adversary.

| Scenario | Decision Modelled | Key Insight |
|---|---|---|
| **patch** | Patch-now vs. defer, against exploit-timing adversary | Rational patch cadence is ~84% of disclosures, not 100% — over-patching wastes resources without proportional security gain |
| **honeypot** | Honeypot on high-value vs. low-value asset | Randomised placement (66/33 split) outperforms deterministic coverage — static honeypots on obvious targets are trivially avoided |
| **ids** | High-sensitivity vs. low-sensitivity IDS | Running high-IDS 81% of the time suppresses stealthy attacks to 12.5% of attacker strategy — attackers avoid expensive evasion when detection is likely |
| **phishing** | Train executives vs. general staff | A 62/38 executive-skewed split is unexploitable; training only executives signals staff are soft targets |

---

## Architecture

```
phronesis.py
└── src/
    ├── cli.py              # argparse entry point, Rich terminal output
    ├── gto_client.py       # Mieza GTO REST API wrapper (POST /v1/nf-solve)
    ├── models.py           # PlayerStrategy, Equilibrium, ScenarioResult dataclasses
    ├── reporter.py         # Self-contained dark-theme HTML report generator
    └── scenarios/
        ├── base.py         # BaseScenario: build_game(), interpret(), run()
        ├── patch.py        # Patch management game
        ├── honeypot.py     # Honeypot placement inspection game
        ├── ids.py          # IDS sensitivity tuning game
        └── phishing.py     # Phishing targeting / training allocation game
```

### Key Design Decisions

**Games as parameterisable templates** — Each scenario encodes the strategic structure of a security decision as a payoff matrix, with cost parameters the user can override to match their environment (e.g. `--param breach_cost=500`). The structural insight — that the attacker adapts to the defender's strategy — holds regardless of the specific numbers. The Nash equilibrium shifts proportionally with the cost inputs, so the tool remains useful even when precise cost data is unavailable.

**Support-enumeration Nash solver via Mieza GTO** — Rather than implementing an equilibrium solver, the tool calls the live Mieza GTO API (`POST /v1/nf-solve`). The solver uses support enumeration, which is exact for 2×2 normal-form games. This keeps the project lightweight while demonstrating real API integration. The solver responds in 2–10ms.

**`interpret()` separates math from meaning** — The `BaseScenario.run()` method handles game construction, API call, and response parsing. Each scenario's `interpret()` method receives the parsed `Equilibrium` and translates probabilities into security-specific language: what the equilibrium means for patch SLAs, honeypot rotation, IDS tuning cycles, or training budget allocation. This keeps the business logic co-located with the game model.

**Mixed strategy is the recommendation** — For most scenarios the equilibrium is a mixed strategy, meaning the optimal policy is explicitly probabilistic. This is an unusual recommendation for security tooling but is precisely correct: deterministic strategies are exploitable. The report presents the full probability distribution alongside the interpretation.

### Stack

- **Language:** Python 3.11+
- **HTTP:** `requests`
- **Terminal UI:** `Rich`
- **Solver:** [Mieza GTO](https://mieza.ai) — support-enumeration Nash solver (live API)

---

## Installation

```bash
git clone https://github.com/MatthewDawkins/security-portfolio
cd project-06-phronesis
pip install -r requirements.txt
export MIEZA_API_KEY=your_key_here  # or pass --api-key on each command
```

## Usage

```bash
# Run all scenarios with default parameters
python phronesis.py run all --output report.html

# Run one scenario
python phronesis.py run patch --verbose

# Override cost parameters to match your environment
python phronesis.py run honeypot --param high_value_asset_loss=500 --param low_value_asset_loss=80

# List all scenarios and their configurable parameters
python phronesis.py scenarios
```

---

## Demo Output

**All four scenarios run live against the Mieza GTO API** using default cost parameters. Results confirmed by the solver:

| Scenario | Defender equilibrium | Attacker equilibrium |
|---|---|---|
| Patch Management | Patch **84.2%**, Defer 15.8% | Exploit **20.0%**, Wait 80.0% |
| Honeypot Placement | Honeypot-A **66.7%**, Honeypot-B 33.3% | Target-B **66.7%**, Target-A 33.3% |
| IDS Sensitivity | High-IDS **81.2%**, Low-IDS 18.8% | Noisy **87.5%**, Stealthy 12.5% |
| Phishing Targeting | Train-Exec **62.5%**, Train-Staff 37.5% | Phish-Staff **62.5%**, Phish-Exec 37.5% |

Full report: [reports/phronesis-demo.html](reports/phronesis-demo.html)

---

## Skills Demonstrated

- Applied game theory: normal-form games, Nash equilibria, mixed strategies, support-enumeration
- Security decision modelling: patch management, deception (honeypots), detection tuning, social engineering defence
- REST API integration (authenticated, production API)
- Python application architecture (abstract base classes, dataclasses, modular scenario system)
- CLI tooling with Rich (live status, formatted tables)
- Programmatic HTML report generation
- Adversarial thinking: framing security decisions as two-player zero-sum and non-zero-sum games
