"""Small shared helpers: timestamp handling and geodesic distance."""
from __future__ import annotations

import math
from datetime import datetime, timezone

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (or date) into an aware UTC datetime.

    Naive values are assumed to already be UTC. Raises ValueError on bad input.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty timestamp")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_ts(dt: datetime) -> str:
    """Format a datetime as normalised UTC text (sorts lexicographically)."""
    return dt.astimezone(timezone.utc).strftime(TS_FORMAT)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    radius = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.asin(min(1.0, math.sqrt(a)))
