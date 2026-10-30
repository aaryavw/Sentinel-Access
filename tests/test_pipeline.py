import json
import os
import unittest

from helpers import AS_OF, build_demo_db, tmpdir
from sentinel.config import PolicyError, load_policy
from sentinel.evaluate import evaluate
from sentinel.generator import generate
from sentinel.report import build_report, md_escape, render_markdown
from sentinel.scanner import run_scan
from sentinel.scoring import band, top_risk, user_risk


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tmpdir()
        cls.conn, cls.manifest, cls.data_dir = build_demo_db(cls._tmp.name)
        cls.policy = load_policy()
        cls.scan = run_scan(cls.conn, cls.policy, AS_OF)
        cls.result = evaluate(cls.conn, os.path.join(cls.data_dir, "ground_truth.json"))

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls._tmp.cleanup()

    def test_every_injected_scenario_is_detected(self):
        for rule, st in self.result["per_rule"].items():
            self.assertEqual(st["false_negative"], 0, f"{rule} missed {st['missed']}")

    def test_no_false_positives_on_benign_baseline(self):
        for rule, st in self.result["per_rule"].items():
            self.assertEqual(st["false_positive"], 0, f"{rule} flagged {st['unexpected']}")
        self.assertEqual(self.result["benign_controls_flagged"], [])

    def test_rescan_is_idempotent_and_preserves_triage(self):
        fid = self.conn.execute("SELECT finding_id FROM findings LIMIT 1").fetchone()[0]
        self.conn.execute("UPDATE findings SET status='false_positive', triaged_by='tester' WHERE finding_id=?", (fid,))
        self.conn.commit()
        total = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        run_scan(self.conn, self.policy, AS_OF)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], total)
        row = self.conn.execute("SELECT status, triaged_by FROM findings WHERE finding_id=?", (fid,)).fetchone()
        self.assertEqual((row["status"], row["triaged_by"]), ("false_positive", "tester"))
        self.conn.execute("UPDATE findings SET status='open', triaged_by=NULL WHERE finding_id=?", (fid,))
        self.conn.commit()

    def test_scoring_ignores_false_positives(self):
        uid = self.conn.execute("SELECT user_id FROM findings WHERE rule_id='stale_account' LIMIT 1").fetchone()[0]
        before = user_risk(self.conn, self.policy, uid)["risk_score"]
        self.conn.execute("UPDATE findings SET status='false_positive' WHERE user_id=?", (uid,))
        self.assertEqual(user_risk(self.conn, self.policy, uid)["risk_score"], 0)
        self.conn.execute("UPDATE findings SET status='open' WHERE user_id=?", (uid,))
        self.assertEqual(user_risk(self.conn, self.policy, uid)["risk_score"], before)

    def test_top_risk_sorted_and_unknown_user(self):
        scores = [p["risk_score"] for p in top_risk(self.conn, self.policy, 50)]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertIsNone(user_risk(self.conn, self.policy, "nobody"))

    def test_report_contents(self):
        report = build_report(self.conn, self.policy)
        self.assertEqual(report["summary"]["total_findings"], self.scan["total"])
        md = render_markdown(report)
        self.assertIn("Synthetic data only", md)
        self.assertIn("Data quality", md)


class UnitTests(unittest.TestCase):
    def test_generator_is_deterministic(self):
        with tmpdir() as a, tmpdir() as b:
            generate(a, seed=7)
            generate(b, seed=7)
            for name in ("users.csv", "entitlements.csv", "access_events.csv", "ground_truth.json"):
                with open(os.path.join(a, name), "rb") as fa, open(os.path.join(b, name), "rb") as fb:
                    self.assertEqual(fa.read(), fb.read(), name)

    def test_generator_rejects_tiny_population(self):
        with tmpdir() as d:
            with self.assertRaises(ValueError):
                generate(d, n_users=10)

    def test_bands(self):
        self.assertEqual([band(s) for s in (0, 10, 25, 60)], ["low", "medium", "high", "critical"])

    def test_markdown_escape(self):
        self.assertEqual(md_escape("a|b\n`c`"), "a\\|b \\`c\\`")

    def test_policy_validation(self):
        with tmpdir() as d:
            path = os.path.join(d, "p.json")
            for bad in ({"stale_dayz": 1}, {"stale_days": -5}, {"business_hours_start_utc": 23},
                        {"toxic_role_pairs": [["a", "a"]]}, {"severity_points": {"high": 1}}):
                with open(path, "w") as fh:
                    json.dump(bad, fh)
                with self.assertRaises(PolicyError, msg=str(bad)):
                    load_policy(path)
            with open(path, "w") as fh:
                json.dump({"stale_days": 30}, fh)
            self.assertEqual(load_policy(path).stale_days, 30)


if __name__ == "__main__":
    unittest.main()
