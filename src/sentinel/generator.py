"""Deterministic synthetic data generator.

Produces three CSV files (users, entitlements, access events) plus:
  * ground_truth.json - which (rule, user) pairs were deliberately injected
  * manifest.json     - seed, reference time and expected quarantine counts

Everything is fabricated: names are ``userNNNN``, IPs come from the RFC 5737
documentation ranges, and locations are public city coordinates. No real
person, system or network is represented.
"""
from __future__ import annotations

import csv
import json
import os
import random
from datetime import datetime, timedelta, timezone

from sentinel.util import fmt_ts

DEFAULT_AS_OF = datetime(2026, 10, 1, tzinfo=timezone.utc)
PRIVILEGED = {"db_admin", "security_admin", "prod_deployer", "domain_admin"}

HOMES = [  # (country, lat, lon)
    ("US", 38.33, -77.04),   # Dahlgren, VA
    ("US", 38.90, -77.04),   # Washington, DC
    ("US", 37.54, -77.44),   # Richmond, VA
    ("US", 36.85, -76.29),   # Norfolk, VA
    ("US", 38.03, -78.48),   # Charlottesville, VA
]
FOREIGN = [("SG", 1.35, 103.82), ("GB", 51.51, -0.13), ("BR", -23.55, -46.63)]

DEPARTMENTS = ["Engineering", "Operations", "Security", "Finance", "HR", "Analytics"]
MIN_USERS = 60


def _base_roles(dept: str, rng: random.Random) -> list[str]:
    if dept == "Engineering":
        return ["developer"]
    if dept == "Operations":
        return [rng.choice(["prod_deployer", "db_admin"])]
    if dept == "Security":
        return [rng.choice(["security_admin", "analyst"])]
    if dept == "Finance":
        return [rng.choice(["requester", "approver", "auditor"])]
    if dept == "HR":
        return ["hr_viewer"]
    return ["analyst", "readonly"]


class _Account:
    def __init__(self, user_id, dept, roles, rng):
        self.user_id = user_id
        self.username = "user" + user_id[1:]
        self.dept = dept
        self.roles = list(roles)
        self.status = "active"
        self.employment = "employed"
        self.termination = None
        self.is_service = False
        self.stop_after = None          # no events at/after this instant
        self.no_priv_after = None       # no privileged commands after this instant
        self.home = rng.choice(HOMES)
        self.last_login = None

    @property
    def privileged(self):
        return bool(PRIVILEGED & set(self.roles))


def generate(outdir: str, seed: int = 1337, n_users: int = 120, days: int = 120,
             as_of: datetime = DEFAULT_AS_OF, dirty: bool = True) -> dict:
    """Write the synthetic dataset to ``outdir`` and return the manifest."""
    if n_users < MIN_USERS:
        raise ValueError(f"n_users must be >= {MIN_USERS} to host every injected scenario")
    rng = random.Random(seed)
    os.makedirs(outdir, exist_ok=True)

    # ---- accounts -----------------------------------------------------
    accounts: list[_Account] = []
    for i in range(n_users):
        dept = DEPARTMENTS[i % len(DEPARTMENTS)]
        accounts.append(_Account(f"u{i + 1:04d}", dept, _base_roles(dept, rng), rng))
    services = []
    for j in range(5):
        svc = _Account(f"s{j + 1:04d}", "Operations", ["prod_deployer"], rng)
        svc.username = f"svc-batch-{j + 1}"
        svc.is_service = True
        services.append(svc)

    nonpriv = [a for a in accounts if not a.privileged]
    priv = [a for a in accounts if a.privileged]
    rng.shuffle(nonpriv)
    rng.shuffle(priv)

    def take(pool, n):
        if len(pool) < n:
            raise ValueError("not enough accounts for the requested scenarios")
        picked = [pool.pop() for _ in range(n)]
        return picked

    truth: list[dict] = []
    controls: list[dict] = []

    def mark(rule, accs, scenario):
        for a in accs:
            truth.append({"rule_id": rule, "user_id": a.user_id, "scenario": scenario})

    # benign controls: correctly offboarded users (disabled, no activity afterwards)
    for a in take(nonpriv, 3):
        a.employment, a.status = "terminated", "disabled"
        a.termination = as_of - timedelta(days=45)
        a.stop_after = a.termination
        controls.append({"user_id": a.user_id, "scenario": "terminated_and_disabled"})
    for s in services:
        controls.append({"user_id": s.user_id, "scenario": "service_account"})

    stale = take(nonpriv, 4)
    for a in stale:
        a.stop_after = as_of - timedelta(days=rng.randint(130, 200))
    mark("stale_account", stale, "no login for 130-200 days")

    orphan_quiet = take(nonpriv, 1)
    orphan_active = take(nonpriv, 2)
    for a in orphan_quiet + orphan_active:
        a.employment, a.termination = "terminated", as_of - timedelta(days=30)
    for a in orphan_quiet:
        a.stop_after = a.termination
    mark("orphaned_account", orphan_quiet, "terminated, account still enabled, no activity")
    mark("orphaned_account", orphan_active, "terminated, account still enabled, activity continues")

    sod_plain = take(nonpriv, 3)
    for a in sod_plain:
        a.roles = ["requester", "approver"]
    mark("separation_of_duties", sod_plain, "requester + approver")
    sod_priv = take([a for a in priv if {"db_admin", "security_admin"} & set(a.roles)], 1)
    priv = [a for a in priv if a not in sod_priv]
    sod_priv[0].roles.append("auditor")
    mark("separation_of_duties", sod_priv, "admin role + auditor")

    unused = take(priv, 3)
    for a in unused:
        a.no_priv_after = as_of - timedelta(days=90)
    mark("unused_privilege", unused, "privileged role unused for 90+ days")

    travel = take(nonpriv, 3)
    mark("impossible_travel", travel, "two logins 30 minutes apart, thousands of km apart")
    brute = take(nonpriv, 3)
    mark("brute_force_success", brute, "7 failed logins then a success within minutes")
    offhrs = take(priv, 3)
    mark("off_hours_privileged", offhrs, "5 privileged commands at 03:00 UTC in the last week")

    # ---- events -------------------------------------------------------
    events: list[dict] = []

    def ev(a, ts, action, resource, ip=None, loc=None):
        country, lat, lon = loc or a.home
        events.append({
            "ts": ts, "user_id": a.user_id, "action": action, "resource": resource,
            "source_ip": ip or f"192.0.2.{rng.randint(1, 254)}",
            "country": country, "lat": lat, "lon": lon,
        })

    start_day = (as_of - timedelta(days=days)).replace(hour=0, minute=0, second=0)
    for a in accounts + services:
        day = start_day
        while day < as_of:
            if a.is_service:
                ev(a, day.replace(hour=3, minute=0), "login", "batch-scheduler")
                ev(a, day.replace(hour=3, minute=5), "privileged_command", "prod-deploy")
                day += timedelta(days=1)
                continue
            weekday = day.weekday() < 5
            if weekday and rng.random() < 0.8:
                t = day.replace(hour=rng.randint(13, 20), minute=rng.randint(0, 59),
                                second=rng.randint(0, 59))
                if a.stop_after is None or t < a.stop_after:
                    if rng.random() < 0.03:
                        ev(a, t - timedelta(minutes=2), "login_failed", "portal")
                    ev(a, t, "login", "portal")
                    if rng.random() < 0.05:
                        ev(a, t + timedelta(minutes=20), "data_export", "reports")
                    if a.privileged and rng.random() < 0.35:
                        tp = t + timedelta(minutes=rng.randint(5, 90))
                        if a.no_priv_after is None or tp < a.no_priv_after:
                            ev(a, tp, "privileged_command", rng.choice(["prod-db", "iam-console", "deploy-pipeline"]))
            day += timedelta(days=1)

    for a in travel:
        d = (as_of - timedelta(days=10)).replace(hour=15, minute=0, second=0)
        ev(a, d, "login", "portal")
        ev(a, d + timedelta(minutes=30), "login", "portal",
           ip=f"203.0.113.{rng.randint(1, 254)}", loc=rng.choice(FOREIGN))
    for a in brute:
        d = (as_of - timedelta(days=6)).replace(hour=14, minute=0, second=0)
        for k in range(7):
            ev(a, d + timedelta(seconds=45 * k), "login_failed", "portal", ip="203.0.113.77")
        ev(a, d + timedelta(seconds=45 * 7 + 30), "login", "portal", ip="203.0.113.77")
    for a in offhrs:
        for k in range(5):
            d = (as_of - timedelta(days=3 + k)).replace(hour=3, minute=10 * k, second=0)
            ev(a, d, "privileged_command", "prod-db")
    for a in orphan_active:  # post-termination exports make the finding critical
        d = (as_of - timedelta(days=5)).replace(hour=16, minute=0, second=0)
        ev(a, d, "data_export", "reports")

    events.sort(key=lambda e: (e["ts"], e["user_id"], e["action"]))
    for n, e in enumerate(events, 1):
        e["event_id"] = f"e{n:07d}"
        if e["action"] == "login":
            acc = next(x for x in accounts + services if x.user_id == e["user_id"])
            if acc.last_login is None or e["ts"] > acc.last_login:
                acc.last_login = e["ts"]

    # ---- write CSVs ---------------------------------------------------
    def write(name, header, rows):
        with open(os.path.join(outdir, name), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)

    everyone = accounts + services
    user_rows = [[a.user_id, a.username, a.dept, a.status, a.employment,
                  fmt_ts(a.termination) if a.termination else "",
                  fmt_ts(a.last_login) if a.last_login else "",
                  int(a.is_service)] for a in everyone]
    ent_rows = [[a.user_id, r, fmt_ts(as_of - timedelta(days=rng.randint(200, 2000)))]
                for a in everyone for r in a.roles]
    ev_rows = [[e["event_id"], fmt_ts(e["ts"]), e["user_id"], e["action"], e["resource"],
                e["source_ip"], e["country"], e["lat"], e["lon"]] for e in events]

    expected_q = {"users": 0, "entitlements": 0, "access_events": 0}
    if dirty:
        user_rows.append(["u9001", "user9001", "Finance", "frozen", "employed", "", "", 0])
        ent_rows.append(["u9999", "analyst", fmt_ts(as_of)])
        good = fmt_ts(as_of - timedelta(days=1))
        ev_rows += [
            ["e9000001", "not-a-date", "u0001", "login", "portal", "192.0.2.1", "US", 38.3, -77.0],
            ["e9000002", good, "u9999", "login", "portal", "192.0.2.1", "US", 38.3, -77.0],
            ["e9000003", good, "u0001", "teleport", "portal", "192.0.2.1", "US", 38.3, -77.0],
            ["e9000004", good, "u0001", "login", "portal", "192.0.2.1", "US", 123.4, -77.0],
            ["e0000001", good, "u0001", "login", "portal", "192.0.2.1", "US", 38.3, -77.0],
            ["e9000006", good, "u0001", "login", "portal", "999.1.1.1", "US", 38.3, -77.0],
        ]
        expected_q = {"users": 1, "entitlements": 1, "access_events": 6}

    write("users.csv", ["user_id", "username", "department", "status", "employment",
                        "termination_date", "last_login", "is_service"], user_rows)
    write("entitlements.csv", ["user_id", "role", "granted_at"], ent_rows)
    write("access_events.csv", ["event_id", "ts", "user_id", "action", "resource",
                                "source_ip", "country", "lat", "lon"], ev_rows)

    manifest = {
        "as_of": fmt_ts(as_of), "seed": seed, "users": len(everyone), "events": len(events),
        "days": days, "expected_quarantine": expected_q,
    }
    with open(os.path.join(outdir, "ground_truth.json"), "w", encoding="utf-8") as fh:
        json.dump({"injected": truth, "benign_controls": controls}, fh, indent=2)
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest
