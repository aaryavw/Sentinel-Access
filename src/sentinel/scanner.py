"""Run every rule and upsert findings, preserving analyst triage state."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime

from sentinel.config import Policy
from sentinel.db import set_meta
from sentinel.rules import RULES, Finding
from sentinel.util import fmt_ts, utcnow


def finding_id(rule_id: str, user_id: str) -> str:
    return hashlib.sha256(f"{rule_id}:{user_id}".encode()).hexdigest()[:16]


def run_scan(conn: sqlite3.Connection, policy: Policy, as_of: datetime) -> dict:
    """Evaluate all rules as of ``as_of``. Returns counts by rule."""
    now = fmt_ts(utcnow())
    counts: dict[str, int] = {}
    for rule in RULES:
        findings: list[Finding] = rule(conn, policy, as_of)
        counts[rule.__name__] = len(findings)
        for f in findings:
            conn.execute(
                "INSERT INTO findings(finding_id, rule_id, user_id, severity, score, title, "
                "detail, evidence, status, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,'open',?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET severity=excluded.severity, "
                "score=excluded.score, title=excluded.title, detail=excluded.detail, "
                "evidence=excluded.evidence, updated_at=excluded.updated_at",
                (finding_id(f.rule_id, f.user_id), f.rule_id, f.user_id, f.severity,
                 policy.points(f.severity), f.title, f.detail,
                 json.dumps(f.evidence, sort_keys=True), now, now))
    set_meta(conn, "last_as_of", fmt_ts(as_of))
    set_meta(conn, "last_scan_at", now)
    conn.commit()
    return {"as_of": fmt_ts(as_of), "findings_by_rule": counts, "total": sum(counts.values())}
