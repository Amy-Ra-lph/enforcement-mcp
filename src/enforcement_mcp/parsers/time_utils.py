"""Convert human-readable time specs to ausearch timestamp format."""

import re
from datetime import UTC, datetime, timedelta


def parse_time_spec(spec: str) -> str:
    """Convert '1h', '30m', '7d' to ausearch -ts format (MM/DD/YYYY HH:MM:SS).

    Also accepts 'recent' (ausearch built-in, last 10 minutes)
    and 'today'/'yesterday' (ausearch built-in).
    """
    spec = spec.strip().lower()

    if spec in ("recent", "today", "yesterday", "this-week", "this-month"):
        return spec

    match = re.match(r"^(\d+)\s*(h|m|d|s)$", spec)
    if not match:
        raise ValueError(f"Invalid time spec: '{spec}'. Use e.g. '1h', '30m', '7d', or 'recent'.")

    amount = int(match.group(1))
    unit = match.group(2)

    delta_map = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    delta = timedelta(**{delta_map[unit]: amount})
    target = datetime.now(UTC) - delta

    return target.strftime("%m/%d/%Y %H:%M:%S")
