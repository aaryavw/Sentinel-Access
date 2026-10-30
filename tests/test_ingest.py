import csv
import os
import unittest

from helpers import build_demo_db, mem_db, tmpdir
from sentinel.generator import generate
from sentinel.ingest import IngestError, ingest_directory


class IngestTests(unittest.TestCase):
    def test_bad_rows_are_quarantined_not_loaded(self):
        with tmpdir() as d:
            conn, manifest, _ = build_demo_db(d)
            expected = manifest["expected_quarantine"]
            rows = conn.execute("SELECT source_file, COUNT(*) n FROM quarantine GROUP BY 1").fetchall()
            got = {r["source_file"]: r["n"] for r in rows}
            self.assertEqual(got["users.csv"], expected["users"])
            self.assertEqual(got["entitlements.csv"], expected["entitlements"])
            self.assertEqual(got["access_events.csv"], expected["access_events"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE user_id='u9001'").fetchone()[0], 0)
            reasons = {r["reason"] for r in conn.execute("SELECT reason FROM quarantine")}
            self.assertTrue({"invalid timestamp in ts", "unknown user_id", "invalid action",
                             "lat out of range", "duplicate key in file", "invalid source_ip",
                             "invalid status"} <= reasons)

    def test_ingest_is_idempotent(self):
        with tmpdir() as d:
            conn, _, data_dir = build_demo_db(d)
            before = [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                      for t in ("users", "entitlements", "access_events")]
            ingest_directory(conn, data_dir)
            after = [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                     for t in ("users", "entitlements", "access_events")]
            self.assertEqual(before, after)

    def test_clean_dataset_has_no_quarantine(self):
        with tmpdir() as d:
            generate(d, dirty=False)
            conn = mem_db()
            ingest_directory(conn, d)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0], 0)

    def test_missing_columns_is_fatal(self):
        with tmpdir() as d:
            generate(d, dirty=False)
            with open(os.path.join(d, "users.csv"), "w", newline="") as fh:
                csv.writer(fh).writerow(["user_id", "username"])
            with self.assertRaises(IngestError):
                ingest_directory(mem_db(), d)

    def test_missing_file_is_fatal(self):
        with tmpdir() as d:
            with self.assertRaises(IngestError):
                ingest_directory(mem_db(), d)

    def test_hostile_identifiers_are_rejected(self):
        with tmpdir() as d:
            generate(d, dirty=False)
            with open(os.path.join(d, "users.csv"), "a", newline="") as fh:
                csv.writer(fh).writerow(["x'; DROP TABLE users;--", "n", "d", "active", "employed", "", "", 0])
            conn = mem_db()
            ingest_directory(conn, d)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM quarantine WHERE reason='invalid user_id'").fetchone()[0], 1)
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 100)

    def test_terminated_requires_date(self):
        with tmpdir() as d:
            generate(d, dirty=False)
            with open(os.path.join(d, "users.csv"), "a", newline="") as fh:
                csv.writer(fh).writerow(["u7777", "n", "d", "active", "terminated", "", "", 0])
            conn = mem_db()
            ingest_directory(conn, d)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM quarantine WHERE reason LIKE 'terminated user%'").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
