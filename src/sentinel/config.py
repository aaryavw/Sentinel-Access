"""Detection policy: thresholds and rules-of-the-road, validated at load time.

Defaults live in code so the tool works with no files; ``config/policy.json``
can override any key. Unknown keys are rejected so typos cannot silently
disable a control.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low")

DEFAULT_POLICY: dict[str, Any] = {
    "stale_days": 90,
    "unused_privilege_days": 60,
    "privileged_roles": ["db_admin", "security_admin", "prod_deployer", "domain_admin"],
    "toxic_role_pairs": [
        ["developer", "prod_deployer"],
        ["requester", "approver"],
        ["security_admin", "auditor"],
        ["db_admin", "auditor"],
    ],
    "business_hours_start_utc": 12,
    "business_hours_end_utc": 22,
    "off_hours_min_events": 3,
    "off_hours_lookback_days": 30,
    "travel_min_distance_km": 500.0,
    "travel_max_speed_kmh": 900.0,
    "brute_force_failed_threshold": 5,
    "brute_force_window_minutes": 10,
    "severity_points": {"critical": 40, "high": 25, "medium": 10, "low": 3},
}


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


@dataclass(frozen=True)
class Policy:
    stale_days: int
    unused_privilege_days: int
    privileged_roles: frozenset
    toxic_role_pairs: tuple
    business_hours_start_utc: int
    business_hours_end_utc: int
    off_hours_min_events: int
    off_hours_lookback_days: int
    travel_min_distance_km: float
    travel_max_speed_kmh: float
    brute_force_failed_threshold: int
    brute_force_window_minutes: int
    severity_points: dict

    def points(self, severity: str) -> int:
        return self.severity_points[severity]


def _pos_int(raw: dict, key: str) -> int:
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyError(f"{key} must be a positive integer")
    return value


def _pos_num(raw: dict, key: str) -> float:
    value = raw[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise PolicyError(f"{key} must be a positive number")
    return float(value)


def _validate(raw: dict) -> Policy:
    roles = raw["privileged_roles"]
    if not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles):
        raise PolicyError("privileged_roles must be a non-empty list of strings")
    pairs = raw["toxic_role_pairs"]
    if not isinstance(pairs, list) or not all(
        isinstance(p, list) and len(p) == 2 and all(isinstance(r, str) for r in p) and p[0] != p[1]
        for p in pairs
    ):
        raise PolicyError("toxic_role_pairs must be a list of two distinct role names")
    start, end = raw["business_hours_start_utc"], raw["business_hours_end_utc"]
    if not (isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= 24):
        raise PolicyError("business hours must satisfy 0 <= start < end <= 24")
    points = raw["severity_points"]
    if not isinstance(points, dict) or set(points) != set(SEVERITIES):
        raise PolicyError(f"severity_points must have exactly the keys {SEVERITIES}")
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in points.values()):
        raise PolicyError("severity_points values must be non-negative integers")
    return Policy(
        stale_days=_pos_int(raw, "stale_days"),
        unused_privilege_days=_pos_int(raw, "unused_privilege_days"),
        privileged_roles=frozenset(roles),
        toxic_role_pairs=tuple(tuple(sorted(p)) for p in pairs),
        business_hours_start_utc=start,
        business_hours_end_utc=end,
        off_hours_min_events=_pos_int(raw, "off_hours_min_events"),
        off_hours_lookback_days=_pos_int(raw, "off_hours_lookback_days"),
        travel_min_distance_km=_pos_num(raw, "travel_min_distance_km"),
        travel_max_speed_kmh=_pos_num(raw, "travel_max_speed_kmh"),
        brute_force_failed_threshold=_pos_int(raw, "brute_force_failed_threshold"),
        brute_force_window_minutes=_pos_int(raw, "brute_force_window_minutes"),
        severity_points=dict(points),
    )


def load_policy(path: str | None = None) -> Policy:
    """Load the default policy, optionally overridden by a JSON file."""
    raw = copy.deepcopy(DEFAULT_POLICY)
    if path:
        with open(path, encoding="utf-8") as fh:
            override = json.load(fh)
        if not isinstance(override, dict):
            raise PolicyError("policy file must contain a JSON object")
        unknown = set(override) - set(DEFAULT_POLICY)
        if unknown:
            raise PolicyError(f"unknown policy keys: {sorted(unknown)}")
        raw.update(override)
    return _validate(raw)
