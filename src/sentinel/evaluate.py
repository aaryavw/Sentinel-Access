"""Compare detections with the generator's ground truth.

IMPORTANT: this measures whether rules catch scenarios the generator injected.
It is a regression harness for the rules, NOT evidence of real-world accuracy.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict


def evaluate(conn: sqlite3.Connection, truth_path: str) -> dict:
    with open(truth_path, encoding="utf-8") as fh:
        truth = json.load(fh)
    expected = {(t["rule_id"], t["user_id"]) for t in truth["injected"]}
    detected = {(r["rule_id"], r["user_id"]) for r in conn.execute("SELECT rule_id, user_id FROM findings")}
    rules = sorted({r for r, _ in expected} | {r for r, _ in detected})
    per_rule = {}
    for rule in rules:
        exp = {u for r, u in expected if r == rule}
        det = {u for r, u in detected if r == rule}
        tp, fp, fn = len(exp & det), len(det - exp), len(exp - det)
        per_rule[rule] = {
            "expected": len(exp), "true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "missed": sorted(exp - det), "unexpected": sorted(det - exp),
        }
    control_ids = {c["user_id"] for c in truth["benign_controls"]}
    control_hits = sorted({u for _, u in detected if u in control_ids})
    totals = defaultdict(int)
    for stats in per_rule.values():
        for k in ("true_positive", "false_positive", "false_negative"):
            totals[k] += stats[k]
    return {"per_rule": per_rule, "totals": dict(totals), "benign_controls_flagged": control_hits}
