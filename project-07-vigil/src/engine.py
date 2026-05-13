"""
Scan engine — feeds events through loaded rules and collects alerts.
"""

from typing import List

from src.correlator import MatchTracker, SequenceTracker, ThresholdTracker
from src.models import Alert, LogEvent
from src.parser import parse_jsonl
from src.rules import load_rules


def run_scan(log_path: str, rules_dir: str) -> tuple[List[LogEvent], List[Alert]]:
    """
    Parse log_path and evaluate every event against rules in rules_dir.

    Returns:
      (events, alerts) — all parsed events and all fired alerts, in time order.
    """
    rules = load_rules(rules_dir)

    match_trackers:     dict = {}
    threshold_trackers: dict = {}
    sequence_trackers:  dict = {}

    for rule in rules:
        rid = rule["id"]
        rtype = rule["type"]
        if rtype == "match":
            match_trackers[rid] = (rule, MatchTracker())
        elif rtype == "threshold":
            threshold_trackers[rid] = (rule, ThresholdTracker())
        elif rtype == "sequence":
            sequence_trackers[rid] = (rule, SequenceTracker())

    events: List[LogEvent] = []
    alerts: List[Alert] = []

    for event in parse_jsonl(log_path):
        events.append(event)

        for rule, tracker in match_trackers.values():
            alert = tracker.process(rule, event)
            if alert:
                alerts.append(alert)

        for rule, tracker in threshold_trackers.values():
            alert = tracker.process(rule, event)
            if alert:
                alerts.append(alert)

        for rule, tracker in sequence_trackers.values():
            alert = tracker.process(rule, event)
            if alert:
                alerts.append(alert)

    alerts.sort(key=lambda a: a.fired_at)
    return events, alerts
