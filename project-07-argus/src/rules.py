"""
Rule loader — reads Sigma-compatible YAML rule files into plain dicts.

Vigil rule schema (Sigma-compatible subset + extensions):

  title        : str            — human-readable rule name
  id           : str            — stable identifier (e.g. vigil-001)
  status       : stable|test    — maturity
  description  : str
  author       : str
  date         : YYYY/MM/DD
  tags         : list           — e.g. [attack.credential_access, attack.t1110.001]
  logsource:
    category   : str            — authentication | network | process | file | cron
    product    : str            — linux | windows | web
  type         : match | threshold | sequence
  detection:
    selection:                  — field: value or field: [val1, val2]
      field_name: value
      field_name|contains: str  — substring match modifier
      field_name|startswith: str
      field_name|endswith: str
    # For threshold rules:
    threshold:
      field      : str          — group-by field (e.g. src_ip)
      count      : int
      timewindow : int          — seconds
    # For sequence rules:
    <step_name>:                — arbitrary step names (must start with 'step')
      field: value ...
    sequence:
      steps    : [step_name, ...]   — ordered list of step names
      correlate: str               — field to correlate steps on (e.g. src_ip)
      maxspan  : int               — max seconds between first and last step
  falsepositives : list[str]
  level          : critical | high | medium | low | informational
  mitre:
    technique : str             — e.g. T1110.001
    tactic    : str
    name      : str
"""

import re
from pathlib import Path
from typing import Any, Dict, List

import yaml


def _load_yaml(path: Path) -> Dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _validate(rule: Dict, path: Path) -> None:
    required = ["title", "id", "type", "detection", "level", "mitre"]
    for key in required:
        if key not in rule:
            raise ValueError(f"Rule {path.name}: missing required field '{key}'")
    rule_type = rule["type"]
    if rule_type not in ("match", "threshold", "sequence"):
        raise ValueError(f"Rule {path.name}: unknown type '{rule_type}'")


def load_rules(rules_dir: str | Path) -> List[Dict]:
    rules_dir = Path(rules_dir)
    rules = []
    for path in sorted(rules_dir.glob("*.yml")):
        rule = _load_yaml(path)
        _validate(rule, path)
        rules.append(rule)
    return rules


# ---------------------------------------------------------------------------
# Selection matching
# ---------------------------------------------------------------------------

_MODIFIER_RE = re.compile(r"^(.+)\|(contains|startswith|endswith)$")


def _field_matches(event_val: Any, pattern: Any) -> bool:
    """Check a single field value against a pattern (exact, list, or None)."""
    if event_val is None:
        return False
    if isinstance(pattern, list):
        return any(_field_matches(event_val, p) for p in pattern)
    return str(event_val).lower() == str(pattern).lower()


def _field_matches_modifier(event_val: Any, modifier: str, pattern: str) -> bool:
    if event_val is None:
        return False
    s = str(event_val).lower()
    p = str(pattern).lower()
    if modifier == "contains":
        return p in s
    if modifier == "startswith":
        return s.startswith(p)
    if modifier == "endswith":
        return s.endswith(p)
    return False


def selection_matches(event, selection: Dict) -> bool:
    """
    Return True if the event satisfies all conditions in the selection dict.
    Supports exact match, list-of-values, and |contains / |startswith / |endswith modifiers.
    """
    for raw_key, pattern in selection.items():
        m = _MODIFIER_RE.match(raw_key)
        if m:
            field, modifier = m.group(1), m.group(2)
            if not _field_matches_modifier(event.raw.get(field), modifier, pattern):
                return False
        else:
            val = event.raw.get(raw_key)
            # event_type is also a top-level attribute
            if val is None and raw_key == "event_type":
                val = event.event_type
            if not _field_matches(val, pattern):
                return False
    return True
