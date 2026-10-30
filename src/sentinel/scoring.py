"""Per-user risk scoring.

Score = sum of severity points over the user's *active* findings (open or
confirmed), capped at 100. False positives and resolved findings do not count,
so analyst triage directly changes the ranking. The scheme is deliberately
simple and explainable; every point can be traced to a finding.
"""
from __future__ import annotations

import sqlite3

from sentinel.config import Policy

ACTIVE_STATUSES = ("open", "confirmed")


def band(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 25:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


def _profile(user_id, username, department, items, policy):
    score = min(100, sum(policy.points(sev) for sev, _ in items))
    return {"user_id": user_id, "username": username, "department": department,
            "risk_score": score, "risk_band": band(score), "active_findings": len(items),
            "rules": sorted({rule for _, rule in items})}


def user_risk(conn: sqlite3.Connection, policy: Policy, user_id: str):
    """Return the risk profile for one user, or None if the user is unknown."""
    user = conn.execute("SELECT user_id, username, department FROM users WHERE user_id = ?",
                        (user_id,)).fetchone()
    if user is None:
        return None
    items = [(r["severity"], r["rule_id"]) for r in conn.execute(
        "SELECT severity, rule_id FROM findings WHERE user_id = ? AND status IN ('open','confirmed')",
        (user_id,))]
    return _profile(user["user_id"], user["username"], user["department"], items, policy)


def top_risk(conn: sqlite3.Connection, policy: Policy, limit: int = 10) -> list[dict]:
    """Highest-risk users with at least one active finding."""
    grouped: dict[str, list] = {}
    for r in conn.execute(
            "SELECT user_id, severity, rule_id FROM findings WHERE status IN ('open','confirmed')"):
        grouped.setdefault(r["user_id"], []).append((r["severity"], r["rule_id"]))
    profiles = []
    for uid, items in grouped.items():
        u = conn.execute("SELECT username, department FROM users WHERE user_id = ?", (uid,)).fetchone()
        profiles.append(_profile(uid, u["username"], u["department"], items, policy))
    profiles.sort(key=lambda p: (-p["risk_score"], p["user_id"]))
    return profiles[:limit]
