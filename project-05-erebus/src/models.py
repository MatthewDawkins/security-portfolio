from dataclasses import dataclass, field
from typing import Optional

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
}


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    url: str
    detail: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
