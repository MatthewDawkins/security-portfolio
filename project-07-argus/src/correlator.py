"""
Correlator — stateful event processing for threshold and sequence rules.

Threshold rules:
  Track a sliding-window count per (rule_id, group_by_value).
  Fire when count >= threshold within the time window.
  Each firing resets the window for that group value, preventing
  duplicate alerts on every subsequent event.

Sequence rules:
  Track a per-(rule_id, correlate_value) state machine.
  Steps must fire in order within maxspan seconds of the first step.
  Completing all steps fires the alert and resets state.
  If maxspan expires, state resets and the current event is retried
  as a potential new sequence start.
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from src.models import Alert, LogEvent
from src.rules import selection_matches
from src import mitre


# ---------------------------------------------------------------------------
# Threshold tracker
# ---------------------------------------------------------------------------

class _ThresholdState:
    __slots__ = ("window", "last_fired_count")

    def __init__(self):
        self.window: deque = deque()           # deque of (timestamp, event)
        self.last_fired_count: int = 0         # count at last alert to avoid re-firing


class ThresholdTracker:
    def __init__(self):
        # (rule_id, group_value) -> _ThresholdState
        self._states: Dict[Tuple, _ThresholdState] = defaultdict(_ThresholdState)

    def process(
        self,
        rule: dict,
        event: LogEvent,
    ) -> Optional[Alert]:
        selection = rule["detection"].get("selection", {})
        if not selection_matches(event, selection):
            return None

        thresh_cfg = rule["detection"]["threshold"]
        group_field = thresh_cfg["field"]
        count_needed = int(thresh_cfg["count"])
        window_secs = int(thresh_cfg["timewindow"])
        group_value = event.raw.get(group_field)
        if group_value is None:
            return None

        key = (rule["id"], group_value)
        state = self._states[key]
        cutoff = event.timestamp - timedelta(seconds=window_secs)

        # Evict expired events
        while state.window and state.window[0][0] < cutoff:
            state.window.popleft()
        state.window.append((event.timestamp, event))

        current_count = len(state.window)
        # Fire on first breach of threshold, then every `count_needed` additional events
        if current_count >= count_needed and current_count > state.last_fired_count:
            state.last_fired_count = current_count
            evidence = [e for _, e in state.window]
            tech = rule["mitre"]["technique"]
            info = mitre.lookup(tech)
            src_events = evidence[:3]  # summarise first few in message
            summary = (
                f"{rule['title']}: {count_needed}+ events from {group_field}={group_value!r} "
                f"in {window_secs}s window ({current_count} total)"
            )
            return Alert(
                rule_id=rule["id"],
                rule_title=rule["title"],
                level=rule["level"],
                mitre_technique=tech,
                mitre_tactic=info.get("tactic", rule["mitre"].get("tactic", "")),
                mitre_name=info.get("name", rule["mitre"].get("name", "")),
                fired_at=event.timestamp,
                evidence=list(evidence),
                summary=summary,
                group_value=str(group_value),
            )
        return None


# ---------------------------------------------------------------------------
# Sequence tracker
# ---------------------------------------------------------------------------

class _SequenceState:
    __slots__ = ("step_index", "start_time", "events")

    def __init__(self):
        self.step_index: int = 0
        self.start_time: Optional[datetime] = None
        self.events: List[LogEvent] = []


class SequenceTracker:
    def __init__(self):
        # (rule_id, correlate_value) -> _SequenceState
        self._states: Dict[Tuple, _SequenceState] = defaultdict(_SequenceState)

    def process(
        self,
        rule: dict,
        event: LogEvent,
    ) -> Optional[Alert]:
        seq_cfg = rule["detection"]["sequence"]
        steps = seq_cfg["steps"]
        correlate_field = seq_cfg["correlate"]
        maxspan = int(seq_cfg["maxspan"])

        correlate_value = event.raw.get(correlate_field)
        if correlate_value is None:
            return None

        key = (rule["id"], correlate_value)
        state = self._states[key]

        # Check if the current open sequence has expired
        if (
            state.start_time is not None
            and (event.timestamp - state.start_time).total_seconds() > maxspan
        ):
            # Reset and fall through — this event may start a new sequence
            self._states[key] = _SequenceState()
            state = self._states[key]

        current_step_name = steps[state.step_index]
        step_selection = rule["detection"].get(current_step_name, {})

        if not selection_matches(event, step_selection):
            return None

        # Event matches current step
        if state.step_index == 0:
            state.start_time = event.timestamp
        state.events.append(event)
        state.step_index += 1

        if state.step_index < len(steps):
            return None  # sequence not yet complete

        # All steps matched — fire alert
        evidence = list(state.events)
        del self._states[key]

        tech = rule["mitre"]["technique"]
        info = mitre.lookup(tech)
        elapsed = (evidence[-1].timestamp - evidence[0].timestamp).total_seconds()
        summary = (
            f"{rule['title']}: {len(steps)}-step sequence completed for "
            f"{correlate_field}={correlate_value!r} over {elapsed:.0f}s"
        )
        return Alert(
            rule_id=rule["id"],
            rule_title=rule["title"],
            level=rule["level"],
            mitre_technique=tech,
            mitre_tactic=info.get("tactic", rule["mitre"].get("tactic", "")),
            mitre_name=info.get("name", rule["mitre"].get("name", "")),
            fired_at=evidence[-1].timestamp,
            evidence=evidence,
            summary=summary,
            group_value=str(correlate_value),
        )


# ---------------------------------------------------------------------------
# Match tracker (stateless — fires immediately)
# ---------------------------------------------------------------------------

class MatchTracker:
    def process(self, rule: dict, event: LogEvent) -> Optional[Alert]:
        selection = rule["detection"].get("selection", {})
        if not selection_matches(event, selection):
            return None
        tech = rule["mitre"]["technique"]
        info = mitre.lookup(tech)
        field_summary = ", ".join(
            f"{k}={event.raw.get(k)!r}"
            for k in ["user", "src_ip", "dest_host", "file_path", "process"]
            if event.raw.get(k)
        )
        summary = f"{rule['title']}: {field_summary or event.event_type}"
        return Alert(
            rule_id=rule["id"],
            rule_title=rule["title"],
            level=rule["level"],
            mitre_technique=tech,
            mitre_tactic=info.get("tactic", rule["mitre"].get("tactic", "")),
            mitre_name=info.get("name", rule["mitre"].get("name", "")),
            fired_at=event.timestamp,
            evidence=[event],
            summary=summary,
        )
