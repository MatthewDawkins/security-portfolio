import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from src.models import LogEvent

_TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
]


def _parse_timestamp(ts: str) -> datetime:
    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    raise ValueError(f"Unrecognised timestamp format: {ts!r}")


def parse_jsonl(path: str | Path) -> Iterator[LogEvent]:
    """
    Parse a JSON-Lines log file into LogEvent objects.

    Each line must be a JSON object containing at minimum:
      - "timestamp"  : ISO-8601 string
      - "event_type" : string identifier for the event class

    All other fields are available via event.get() / event.raw.
    Lines beginning with '#' are treated as comments and skipped.
    """
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Line {lineno}: invalid JSON — {exc}") from exc

            ts_raw = obj.get("timestamp")
            if not ts_raw:
                raise ValueError(f"Line {lineno}: missing 'timestamp' field")

            event_type = obj.get("event_type")
            if not event_type:
                raise ValueError(f"Line {lineno}: missing 'event_type' field")

            yield LogEvent(
                timestamp=_parse_timestamp(ts_raw),
                event_type=event_type,
                raw=obj,
            )
