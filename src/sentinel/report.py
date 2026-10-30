"""JSON and Markdown reporting."""
from __future__ import annotations

import json
import os
import sqlite3
from collections import Counter

from sentinel.config import SEVERITIES, Policy
from sentinel.db import get_meta
from sentinel.scoring import top_risk


def md_escape(value) -> str:
    """Neutralise characters that could break Markdown tables or inject formatting."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    for ch in ("\\", "|", "`", "*", "_", "<", ">", "[", "]"):
        text = text.replace(ch, "\\" + ch)
    return text


def build_report(conn: sqlite3.Connection, policy: Policy) -> dict:
    rows = conn.execute(
        "SELECT f.finding_id, f.rule_id, f.user_id, u.username, u.department, f.severity, "
        "f.title, f.detail, f.status FROM findings f JOIN users u ON u.user_id = f.user_id "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, f.user_id, f.rule_id").fetchall()
    findings = [dict(r) for r in rows]
    by_sev = Counter(f["severity"] for f in findings)
    by_rule = Counter(f["rule_id"] for f in findings)
    q = conn.execute("SELECT source_file, COUNT(*) AS n FROM quarantine GROUP BY source_file").fetchall()
    return {
        "as_of": get_meta(conn, "last_as_of"),
        "summary": {"total_findings": len(findings),
                    "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
                    "by_rule": dict(sorted(by_rule.items()))},
        "data_quality": {"quarantined_rows": {r["source_file"]: r["n"] for r in q}},
        "top_risk_users": top_risk(conn, policy, 10),
        "findings": findings,
    }


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = ["# SentinelAccess Report", "",
             f"Reference time (as-of): `{report['as_of']}`", "",
             "> Synthetic data only. Findings are leads for human review, not verdicts.", "",
             "## Summary", "",
             f"Total findings: **{s['total_findings']}**", "",
             "| Severity | Count |", "|---|---|"]
    lines += [f"| {sev} | {s['by_severity'][sev]} |" for sev in SEVERITIES]
    lines += ["", "| Rule | Count |", "|---|---|"]
    lines += [f"| {md_escape(rule)} | {n} |" for rule, n in s["by_rule"].items()]
    lines += ["", "## Data quality", ""]
    quarantined = report["data_quality"]["quarantined_rows"]
    if quarantined:
        lines += [f"- {md_escape(f)}: {n} row(s) quarantined" for f, n in quarantined.items()]
    else:
        lines.append("- No rows quarantined.")
    lines += ["", "## Highest-risk users", "",
              "| User | Dept | Risk | Band | Rules |", "|---|---|---|---|---|"]
    for p in report["top_risk_users"]:
        lines.append(f"| {md_escape(p['username'])} | {md_escape(p['department'])} | "
                     f"{p['risk_score']} | {p['risk_band']} | {md_escape(', '.join(p['rules']))} |")
    lines += ["", "## Findings", ""]
    for f in report["findings"]:
        lines.append(f"- **{f['severity'].upper()}** `{f['finding_id']}` {md_escape(f['title'])}"
                     f" - {md_escape(f['detail'])} _(status: {f['status']})_")
    return "\n".join(lines) + "\n"


def write_reports(conn: sqlite3.Connection, policy: Policy, outdir: str) -> tuple[str, str]:
    os.makedirs(outdir, exist_ok=True)
    report = build_report(conn, policy)
    jpath, mpath = os.path.join(outdir, "report.json"), os.path.join(outdir, "report.md")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(mpath, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))
    return jpath, mpath
