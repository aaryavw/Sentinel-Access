"""Detection rules.

Each rule is a pure function ``(conn, policy, as_of) -> list[Finding]`` that
reads from the database and emits at most ONE finding per (rule, user). That
keeps finding IDs stable across re-scans so analyst triage is never lost.
"""
from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from itertools import groupby

from sentinel.config import Policy
from sentinel.util import fmt_ts, haversine_km, parse_ts


@dataclass
class Finding:
    rule_id: str
    user_id: str
    severity: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)


def _roles_by_user(conn):
    roles = defaultdict(set)
    for row in conn.execute("SELECT user_id, role FROM entitlements"):
        roles[row["user_id"]].add(row["role"])
    return roles


def _active_humans(conn):
    return conn.execute(
        "SELECT user_id, username, last_login FROM users "
        "WHERE status = 'active' AND employment = 'employed' AND is_service = 0 "
        "ORDER BY user_id").fetchall()


def stale_account(conn, policy: Policy, as_of: datetime) -> list[Finding]:
    """Enabled accounts with no recent login are unmanaged attack surface."""
    cutoff = as_of - timedelta(days=policy.stale_days)
    roles = _roles_by_user(conn)
    out = []
    for row in _active_humans(conn):
        last = parse_ts(row["last_login"]) if row["last_login"] else None
        if last is not None and last >= cutoff:
            continue
        priv = sorted(roles[row["user_id"]] & policy.privileged_roles)
        age = (as_of - last).days if last else None
        out.append(Finding(
            "stale_account", row["user_id"], "high" if priv else "medium",
            "Enabled account with no recent login",
            (f"{row['username']} has never logged in (policy: {policy.stale_days} days)."
             if age is None else
             f"{row['username']} has not logged in for {age} days (policy: {policy.stale_days})."),
            {"last_login": row["last_login"], "days_inactive": age, "privileged_roles": priv}))
    return out


def orphaned_account(conn, policy: Policy, as_of: datetime) -> list[Finding]:
    """Terminated employees whose accounts are still enabled or still in use."""
    out = []
    rows = conn.execute(
        "SELECT user_id, username, status, termination_date FROM users "
        "WHERE employment = 'terminated' ORDER BY user_id").fetchall()
    for row in rows:
        post = conn.execute(
            "SELECT COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM access_events "
            "WHERE user_id = ? AND ts > ? AND action != 'login_failed'",
            (row["user_id"], row["termination_date"])).fetchone()
        if post["n"] > 0:
            out.append(Finding(
                "orphaned_account", row["user_id"], "critical",
                "Activity after termination",
                f"{row['username']} was terminated {row['termination_date']} but "
                f"{post['n']} successful events occurred afterwards.",
                {"termination_date": row["termination_date"], "events_after": post["n"],
                 "first_event": post["first_ts"], "last_event": post["last_ts"],
                 "account_status": row["status"]}))
        elif row["status"] == "active":
            out.append(Finding(
                "orphaned_account", row["user_id"], "high",
                "Terminated employee account still enabled",
                f"{row['username']} was terminated {row['termination_date']} but the "
                "account remains enabled.",
                {"termination_date": row["termination_date"], "account_status": "active"}))
    return out


def separation_of_duties(conn, policy: Policy, as_of: datetime) -> list[Finding]:
    """Users holding two roles the policy declares mutually exclusive."""
    roles = _roles_by_user(conn)
    out = []
    for row in _active_humans(conn):
        held = roles[row["user_id"]]
        hits = [list(p) for p in policy.toxic_role_pairs if set(p) <= held]
        if hits:
            out.append(Finding(
                "separation_of_duties", row["user_id"], "high",
                "Conflicting roles held by one user",
                f"{row['username']} holds conflicting roles: "
                + "; ".join(" + ".join(p) for p in hits) + ".",
                {"conflicts": hits, "all_roles": sorted(held)}))
    return out


def unused_privilege(conn, policy: Policy, as_of: datetime) -> list[Finding]:
    """Least-privilege check: privileged roles that are never exercised."""
    cutoff = as_of - timedelta(days=policy.unused_privilege_days)
    last_used = {r["user_id"]: r["last_ts"] for r in conn.execute(
        "SELECT user_id, MAX(ts) AS last_ts FROM access_events "
        "WHERE action = 'privileged_command' GROUP BY user_id")}
    roles = _roles_by_user(conn)
    out = []
    for row in _active_humans(conn):
        priv = sorted(roles[row["user_id"]] & policy.privileged_roles)
        if not priv:
            continue
        last = last_used.get(row["user_id"])
        if last is not None and parse_ts(last) >= cutoff:
            continue
        out.append(Finding(
            "unused_privilege", row["user_id"], "medium",
            "Privileged role not exercised recently",
            f"{row['username']} holds {', '.join(priv)} but ran no privileged command in "
            f"{policy.unused_privilege_days} days. Consider revoking.",
            {"privileged_roles": priv, "last_privileged_command": last}))
    return out


def impossible_travel(conn, policy: Policy, as_of: datetime) -> list[Finding]:
    """Consecutive logins whose implied speed exceeds what travel allows."""
    rows = conn.execute(
        "SELECT event_id, ts, user_id, country, lat, lon FROM access_events "
        "WHERE action = 'login' AND lat IS NOT NULL AND lon IS NOT NULL "
        "ORDER BY user_id, ts").fetchall()
    names = {r["user_id"]: r["username"] for r in conn.execute("SELECT user_id, username FROM users")}
    out = []
    for user_id, group in groupby(rows, key=lambda r: r["user_id"]):
        prev, hits = None, []
        for cur in group:
            if prev is not None:
                dist = haversine_km(prev["lat"], prev["lon"], cur["lat"], cur["lon"])
                hours = (parse_ts(cur["ts"]) - parse_ts(prev["ts"])).total_seconds() / 3600
                speed = dist / max(hours, 1 / 3600)
                if dist >= policy.travel_min_distance_km and speed > policy.travel_max_speed_kmh:
                    hits.append({"from_event": prev["event_id"], "to_event": cur["event_id"],
                                 "from_ts": prev["ts"], "to_ts": cur["ts"],
                                 "from_country": prev["country"], "to_country": cur["country"],
                                 "distance_km": round(dist), "speed_kmh": round(speed)})
            prev = cur
        if hits:
            worst = max(hits, key=lambda h: h["speed_kmh"])
            out.append(Finding(
                "impossible_travel", user_id, "high", "Impossible travel between logins",
                f"{names.get(user_id, user_id)}: {len(hits)} login pair(s) imply travel above "
                f"{policy.travel_max_speed_kmh:.0f} km/h (worst {worst['distance_km']} km in "
                f"{worst['from_ts']} -> {worst['to_ts']}).",
                {"occurrences": len(hits), "examples": hits[:5]}))
    return out


def brute_force_success(conn, policy: Policy, as_of: datetime) -> list[Finding]:
    """A burst of failed logins immediately followed by a success."""
    window = timedelta(minutes=policy.brute_force_window_minutes)
    roles = _roles_by_user(conn)
    names = {r["user_id"]: r["username"] for r in conn.execute("SELECT user_id, username FROM users")}
    rows = conn.execute(
        "SELECT event_id, ts, user_id, action FROM access_events "
        "WHERE action IN ('login', 'login_failed') ORDER BY user_id, ts").fetchall()
    out = []
    for user_id, group in groupby(rows, key=lambda r: r["user_id"]):
        events = [(parse_ts(r["ts"]), r["event_id"], r["action"]) for r in group]
        failed = [t for t, _, a in events if a == "login_failed"]
        hits = []
        for t, event_id, action in events:
            if action != "login":
                continue
            count = bisect_left(failed, t) - bisect_left(failed, t - window)
            if count >= policy.brute_force_failed_threshold:
                hits.append({"success_event": event_id, "success_ts": fmt_ts(t),
                             "failed_in_window": count})
        if hits:
            priv = bool(roles[user_id] & policy.privileged_roles)
            out.append(Finding(
                "brute_force_success", user_id, "critical" if priv else "high",
                "Successful login after burst of failures",
                f"{names.get(user_id, user_id)}: {hits[0]['failed_in_window']} failed logins "
                f"within {policy.brute_force_window_minutes} min preceded a success.",
                {"occurrences": len(hits), "examples": hits[:5], "privileged": priv}))
    return out


def off_hours_privileged(conn, policy: Policy, as_of: datetime) -> list[Finding]:
    """Privileged commands run outside business hours by human accounts."""
    since = fmt_ts(as_of - timedelta(days=policy.off_hours_lookback_days))
    rows = conn.execute(
        "SELECT e.event_id, e.ts, e.user_id, u.username FROM access_events e "
        "JOIN users u ON u.user_id = e.user_id "
        "WHERE e.action = 'privileged_command' AND e.ts >= ? AND e.ts <= ? "
        "AND u.is_service = 0 AND u.status = 'active' ORDER BY e.user_id, e.ts",
        (since, fmt_ts(as_of))).fetchall()
    out = []
    for user_id, group in groupby(rows, key=lambda r: r["user_id"]):
        hits = [r for r in group
                if not (policy.business_hours_start_utc <= parse_ts(r["ts"]).hour
                        < policy.business_hours_end_utc)]
        if len(hits) >= policy.off_hours_min_events:
            out.append(Finding(
                "off_hours_privileged", user_id, "high" if len(hits) >= 10 else "medium",
                "Privileged activity outside business hours",
                f"{hits[0]['username']} ran {len(hits)} privileged commands outside "
                f"{policy.business_hours_start_utc:02d}:00-{policy.business_hours_end_utc:02d}:00 UTC "
                f"in the last {policy.off_hours_lookback_days} days.",
                {"count": len(hits), "event_ids": [h["event_id"] for h in hits[:10]],
                 "first": hits[0]["ts"], "last": hits[-1]["ts"]}))
    return out


RULES = [stale_account, orphaned_account, separation_of_duties, unused_privilege,
         impossible_travel, brute_force_success, off_hours_privileged]
