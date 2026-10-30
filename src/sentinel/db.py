"""SQLite schema and connection helper. All queries elsewhere are parameterised."""
from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    department TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    employment TEXT NOT NULL CHECK (employment IN ('employed', 'terminated')),
    termination_date TEXT,
    last_login TEXT,
    is_service INTEGER NOT NULL DEFAULT 0 CHECK (is_service IN (0, 1))
);
CREATE TABLE IF NOT EXISTS entitlements (
    user_id TEXT NOT NULL REFERENCES users(user_id),
    role TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
);
CREATE TABLE IF NOT EXISTS access_events (
    event_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    action TEXT NOT NULL CHECK (action IN ('login', 'login_failed', 'privileged_command', 'data_export')),
    resource TEXT,
    source_ip TEXT,
    country TEXT,
    lat REAL,
    lon REAL
);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON access_events(user_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_action_ts ON access_events(action, ts);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    score INTEGER NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'confirmed', 'false_positive', 'resolved')),
    triaged_by TEXT,
    triage_note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    reason TEXT NOT NULL,
    raw TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None
