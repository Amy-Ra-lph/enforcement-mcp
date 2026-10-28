"""Convert human-readable time specs to ausearch timestamp format.

Uses target-side $(date) shell substitution so the timestamp is
computed in the target host's timezone, not the controller's.
"""

import re

from ._hardening import validate_input_size

_UNIT_WORDS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_time_spec(spec: str) -> str:
    """Convert '1h', '30m', '7d' to a shell expression for ausearch -ts.

    Returns either an ausearch built-in keyword (recent/today/yesterday)
    or a $(date ...) expression evaluated on the target host.
    """
    validate_input_size(spec, "parse_time_spec")
    spec = spec.strip().lower()

    if spec in ("recent", "today", "yesterday", "this-week", "this-month"):
        return spec

    match = re.match(r"^(\d+)\s*(h|m|d|s)$", spec)
    if not match:
        raise ValueError(f"Invalid time spec: '{spec}'. Use e.g. '1h', '30m', '7d', or 'recent'.")

    amount = int(match.group(1))
    unit = match.group(2)

    return f"$(date -d '-{amount} {_UNIT_WORDS[unit]}' '+%m/%d/%Y %H:%M:%S')"
