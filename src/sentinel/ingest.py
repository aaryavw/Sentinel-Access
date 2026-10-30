"""Validating CSV -> SQLite ingestion with a quarantine table.

Design: every row is validated independently. Bad rows never abort the load;
they are written to ``quarantine`` with a reason so data-quality problems are
visible and auditable instead of silently dropped. Loading is idempotent.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import sqlite3
from dataclasses import dataclass

from sentinel.util import fmt_ts, parse_ts

ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
ACTIONS = {"login", "login_failed", "privileged_command", "data_export"}
MAX_FIELD = 200

USER_COLS = ["user_id", "username", "department", "status", "employment",
             "termination_date", "last_login", "is_service"]
ENT_COLS = ["user_id", "role", "granted_at"]
EVENT_COLS = ["event_id", "ts", "user_id", "action", "resource", "source_ip",
              "country", "lat", "lon"]


class IngestError(Exception):
    """Fatal problem with an input file (e.g. missing columns)."""


@dataclass
class IngestResult:
    table: str
    read: int = 0
    loaded: int = 0
    quarantined: int = 0

    def as_dict(self):
        return {"table": self.table, "read": self.read, "loaded": self.loaded,
                "quarantined": self.quarantined}


def _text(row, key, required=True):
    value = (row.get(key) or "").strip()
    if required and not value:
        raise ValueError(f"missing {key}")
    if len(value) > MAX_FIELD:
        raise ValueError(f"{key} too long")
    return value


def _ident(row, key):
    value = _text(row, key)
    if not ID_RE.match(value):
        raise ValueError(f"invalid {key}")
    return value


def _opt_ts(row, key):
    value = _text(row, key, required=False)
    if not value:
        return None
    try:
        return fmt_ts(parse_ts(value))
    except ValueError:
        raise ValueError(f"invalid timestamp in {key}") from None


def _req_ts(row, key):
    value = _opt_ts(row, key)
    if value is None:
        raise ValueError(f"missing {key}")
    return value


def _validate_user(row):
    status = _text(row, "status")
    employment = _text(row, "employment")
    if status not in ("active", "disabled"):
        raise ValueError("invalid status")
    if employment not in ("employed", "terminated"):
        raise ValueError("invalid employment")
    term = _opt_ts(row, "termination_date")
    if employment == "terminated" and term is None:
        raise ValueError("terminated user requires termination_date")
    svc = _text(row, "is_service", required=False).lower() or "0"
    if svc not in ("0", "1", "true", "false"):
        raise ValueError("invalid is_service")
    return (_ident(row, "user_id"), _text(row, "username"), _text(row, "department"),
            status, employment, term, _opt_ts(row, "last_login"),
            1 if svc in ("1", "true") else 0)


def _validate_ent(row, known_users):
    user_id = _ident(row, "user_id")
    if user_id not in known_users:
        raise ValueError("unknown user_id")
    role = _text(row, "role")
    if not ROLE_RE.match(role):
        raise ValueError("invalid role")
    return (user_id, role, _req_ts(row, "granted_at"))


def _opt_float(row, key, lo, hi):
    value = _text(row, key, required=False)
    if not value:
        return None
    try:
        num = float(value)
    except ValueError:
        raise ValueError(f"invalid {key}") from None
    if not (lo <= num <= hi) or num != num:
        raise ValueError(f"{key} out of range")
    return num


def _validate_event(row, known_users):
    user_id = _ident(row, "user_id")
    if user_id not in known_users:
        raise ValueError("unknown user_id")
    action = _text(row, "action")
    if action not in ACTIONS:
        raise ValueError("invalid action")
    ip = _text(row, "source_ip", required=False) or None
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("invalid source_ip") from None
    country = _text(row, "country", required=False) or None
    if country and not COUNTRY_RE.match(country):
        raise ValueError("invalid country")
    lat = _opt_float(row, "lat", -90, 90)
    lon = _opt_float(row, "lon", -180, 180)
    if (lat is None) != (lon is None):
        raise ValueError("lat/lon must be given together")
    return (_ident(row, "event_id"), _req_ts(row, "ts"), user_id, action,
            _text(row, "resource", required=False) or None, ip, country, lat, lon)


def _rows(path, expected_cols):
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = set(expected_cols) - set(reader.fieldnames or [])
        if missing:
            raise IngestError(f"{os.path.basename(path)} is missing columns: {sorted(missing)}")
        for row in reader:
            yield reader.line_num, row


def _load(conn, path, table, cols, validate, insert_sql, id_of):
    result = IngestResult(table)
    seen = set()
    name = os.path.basename(path)
    for line_no, row in _rows(path, cols):
        result.read += 1
        try:
            values = validate(row)
            key = id_of(values)
            if key in seen:
                raise ValueError("duplicate key in file")
            seen.add(key)
            conn.execute(insert_sql, values)
            result.loaded += 1
        except (ValueError, sqlite3.IntegrityError) as exc:
            result.quarantined += 1
            raw = json.dumps({k: (v or "")[:80] for k, v in row.items() if k}, sort_keys=True)
            conn.execute(
                "INSERT INTO quarantine(source_file, line_no, reason, raw) VALUES(?,?,?,?)",
                (name, line_no, str(exc)[:200], raw[:500]))
    return result


def ingest_directory(conn: sqlite3.Connection, directory: str) -> list[IngestResult]:
    """Load users, entitlements and access events from ``directory``."""
    users_p = os.path.join(directory, "users.csv")
    ent_p = os.path.join(directory, "entitlements.csv")
    ev_p = os.path.join(directory, "access_events.csv")
    for p in (users_p, ent_p, ev_p):
        if not os.path.isfile(p):
            raise IngestError(f"missing input file: {p}")

    conn.execute("DELETE FROM quarantine")  # quarantine reflects the latest run
    results = [_load(
        conn, users_p, "users", USER_COLS, _validate_user,
        "INSERT INTO users(user_id, username, department, status, employment, "
        "termination_date, last_login, is_service) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, "
        "department=excluded.department, status=excluded.status, "
        "employment=excluded.employment, termination_date=excluded.termination_date, "
        "last_login=excluded.last_login, is_service=excluded.is_service",
        lambda v: v[0])]
    known = {r[0] for r in conn.execute("SELECT user_id FROM users")}
    results.append(_load(
        conn, ent_p, "entitlements", ENT_COLS, lambda r: _validate_ent(r, known),
        "INSERT INTO entitlements(user_id, role, granted_at) VALUES(?,?,?) "
        "ON CONFLICT(user_id, role) DO UPDATE SET granted_at=excluded.granted_at",
        lambda v: (v[0], v[1])))
    results.append(_load(
        conn, ev_p, "access_events", EVENT_COLS, lambda r: _validate_event(r, known),
        "INSERT OR IGNORE INTO access_events(event_id, ts, user_id, action, resource, "
        "source_ip, country, lat, lon) VALUES(?,?,?,?,?,?,?,?,?)",
        lambda v: v[0]))
    conn.commit()
    return results
