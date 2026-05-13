from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class LogEvent:
    timestamp: datetime
    event_type: str
    raw: Dict[str, Any]

    def get(self, key: str, default=None):
        return self.raw.get(key, default)

    def __repr__(self):
        ts = self.timestamp.strftime("%H:%M:%S")
        src = self.raw.get("src_ip", "")
        host = self.raw.get("dest_host", self.raw.get("host", ""))
        user = self.raw.get("user", "")
        parts = [p for p in [ts, self.event_type, src, host, user] if p]
        return f"<Event {' | '.join(parts)}>"


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    level: str
    mitre_technique: str
    mitre_tactic: str
    mitre_name: str
    fired_at: datetime
    evidence: List[LogEvent]
    summary: str
    group_value: Optional[str] = None   # the correlated field value (e.g. src_ip)

    @property
    def level_rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(
            self.level, 5
        )
