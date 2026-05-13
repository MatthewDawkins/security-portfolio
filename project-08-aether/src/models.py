"""
Data models for Stratus findings.
"""

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#44aaff",
    "info":     "#888888",
}


@dataclass
class Finding:
    check_id:       str
    title:          str
    severity:       str           # critical | high | medium | low | info
    service:        str           # IAM | S3 | EC2 | RDS | CloudTrail | VPC
    resource_type:  str
    resource_id:    str
    region:         str
    description:    str
    recommendation: str
    mitre_technique: Optional[str] = None
    mitre_tactic:    Optional[str] = None
    mitre_name:      Optional[str] = None

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity.lower(), 99)

    @property
    def severity_color(self) -> str:
        return SEVERITY_COLOR.get(self.severity.lower(), "#888888")
