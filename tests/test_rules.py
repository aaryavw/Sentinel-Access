import unittest
from datetime import timedelta

from helpers import AS_OF, add_event, add_user, ago, mem_db
from sentinel import rules
from sentinel.config import load_policy

P = load_policy()


class StaleAccountTests(unittest.TestCase):
    def test_boundary_and_exclusions(self):
        c = mem_db()
        add_user(c, "fresh", last_login="2026-09-20T00:00:00Z")
        add_user(c, "edge_ok", last_login="2026-07-03T00:00:00Z")     # exactly 90 days
        add_user(c, "old", last_login="2026-07-02T23:59:59Z")        # just over
        add_user(c, "never", last_login=None)
        add_user(c, "svc", last_login="2020-01-01T00:00:00Z", service=1)
        add_user(c, "off", status="disabled", last_login="2020-01-01T00:00:00Z")
        got = {f.user_id: f for f in rules.stale_account(c, P, AS_OF)}
        self.assertEqual(set(got), {"old", "never"})
        self.assertEqual(got["old"].severity, "medium")

    def test_privileged_stale_is_high(self):
        c = mem_db()
        add_user(c, "adm", last_login="2026-01-01T00:00:00Z", roles=["db_admin"])
        self.assertEqual(rules.stale_account(c, P, AS_OF)[0].severity, "high")


class OrphanedAccountTests(unittest.TestCase):
    def test_levels(self):
        c = mem_db()
        add_user(c, "quiet", employment="terminated", term="2026-09-01T00:00:00Z")
        add_user(c, "busy", employment="terminated", term="2026-09-01T00:00:00Z")
        add_user(c, "clean", status="disabled", employment="terminated", term="2026-09-01T00:00:00Z")
        add_user(c, "failed_only", status="disabled", employment="terminated", term="2026-09-01T00:00:00Z")
        add_event(c, "busy", "2026-09-10T10:00:00Z")
        add_event(c, "clean", "2026-08-30T10:00:00Z")           # before termination: fine
        add_event(c, "failed_only", "2026-09-10T10:00:00Z", action="login_failed")
        got = {f.user_id: f.severity for f in rules.orphaned_account(c, P, AS_OF)}
        self.assertEqual(got, {"quiet": "high", "busy": "critical"})


class SeparationOfDutiesTests(unittest.TestCase):
    def test_detects_configured_pairs_only(self):
        c = mem_db()
        add_user(c, "bad", roles=["requester", "approver"])
        add_user(c, "ok", roles=["requester", "analyst"])
        add_user(c, "bad2", roles=["auditor", "security_admin", "readonly"])
        got = {f.user_id for f in rules.separation_of_duties(c, P, AS_OF)}
        self.assertEqual(got, {"bad", "bad2"})


class UnusedPrivilegeTests(unittest.TestCase):
    def test_usage_window(self):
        c = mem_db()
        add_user(c, "active_admin", roles=["db_admin"])
        add_user(c, "idle_admin", roles=["db_admin"])
        add_user(c, "never_used", roles=["prod_deployer"])
        add_user(c, "plain", roles=["developer"])
        add_user(c, "svc", roles=["prod_deployer"], service=1)
        add_event(c, "active_admin", ago(days=10), "privileged_command")
        add_event(c, "idle_admin", ago(days=61), "privileged_command")
        got = {f.user_id for f in rules.unused_privilege(c, P, AS_OF)}
        self.assertEqual(got, {"idle_admin", "never_used"})


class ImpossibleTravelTests(unittest.TestCase):
    def test_fast_hop_flagged_slow_hop_not(self):
        c = mem_db()
        add_user(c, "fast")
        add_user(c, "slow")
        add_user(c, "local")
        add_event(c, "fast", ago(hours=5))
        add_event(c, "fast", ago(hours=4, minutes=30), lat=51.51, lon=-0.13, country="GB")
        add_event(c, "slow", ago(hours=30))
        add_event(c, "slow", ago(hours=2), lat=51.51, lon=-0.13, country="GB")   # ~200 km/h
        add_event(c, "local", ago(hours=5))
        add_event(c, "local", ago(minutes=290), lat=38.90, lon=-77.04)           # ~60 km: under min distance
        got = rules.impossible_travel(c, P, AS_OF)
        self.assertEqual([f.user_id for f in got], ["fast"])
        self.assertGreater(got[0].evidence["examples"][0]["speed_kmh"], 900)

    def test_identical_timestamps_do_not_divide_by_zero(self):
        c = mem_db()
        add_user(c, "u")
        add_event(c, "u", ago(hours=1))
        add_event(c, "u", ago(hours=1), lat=1.35, lon=103.82, country="SG")
        self.assertEqual(len(rules.impossible_travel(c, P, AS_OF)), 1)


class BruteForceTests(unittest.TestCase):
    def _burst(self, c, uid, n, success=True):
        base = ago(hours=3)
        for i in range(n):
            add_event(c, uid, base + timedelta(seconds=30 * i), "login_failed")
        if success:
            add_event(c, uid, base + timedelta(seconds=30 * n + 5), "login")

    def test_threshold(self):
        c = mem_db()
        for uid in ("four", "five", "no_success"):
            add_user(c, uid)
        self._burst(c, "four", 4)
        self._burst(c, "five", 5)
        self._burst(c, "no_success", 9, success=False)
        self.assertEqual([f.user_id for f in rules.brute_force_success(c, P, AS_OF)], ["five"])

    def test_failures_outside_window_do_not_count(self):
        c = mem_db()
        add_user(c, "slow")
        for i in range(6):   # one failure every 3 minutes: never 5 inside 10 minutes
            add_event(c, "slow", ago(hours=2) + timedelta(minutes=3 * i), "login_failed")
        add_event(c, "slow", ago(hours=2) + timedelta(minutes=19))
        self.assertEqual(rules.brute_force_success(c, P, AS_OF), [])

    def test_privileged_user_is_critical(self):
        c = mem_db()
        add_user(c, "adm", roles=["security_admin"])
        self._burst(c, "adm", 6)
        self.assertEqual(rules.brute_force_success(c, P, AS_OF)[0].severity, "critical")


class OffHoursTests(unittest.TestCase):
    def test_counts_and_exclusions(self):
        c = mem_db()
        add_user(c, "night", roles=["db_admin"])
        add_user(c, "few", roles=["db_admin"])
        add_user(c, "day", roles=["db_admin"])
        add_user(c, "svc", roles=["prod_deployer"], service=1)
        for d in range(3):
            add_event(c, "night", ago(days=d + 1).replace(hour=3), "privileged_command")
            add_event(c, "svc", ago(days=d + 1).replace(hour=3), "privileged_command")
            add_event(c, "day", ago(days=d + 1).replace(hour=15), "privileged_command")
        for d in range(2):
            add_event(c, "few", ago(days=d + 1).replace(hour=3), "privileged_command")
        add_event(c, "night", ago(days=45).replace(hour=3), "privileged_command")  # outside lookback
        got = rules.off_hours_privileged(c, P, AS_OF)
        self.assertEqual([f.user_id for f in got], ["night"])
        self.assertEqual(got[0].evidence["count"], 3)

    def test_business_hour_edges(self):
        c = mem_db()
        add_user(c, "edge", roles=["db_admin"])
        for h in (12, 21, 21):   # inside [12, 22)
            add_event(c, "edge", ago(days=1).replace(hour=h), "privileged_command")
        self.assertEqual(rules.off_hours_privileged(c, P, AS_OF), [])
        add_event(c, "edge", ago(days=2).replace(hour=22), "privileged_command")  # 22:00 is outside
        add_event(c, "edge", ago(days=3).replace(hour=11), "privileged_command")
        add_event(c, "edge", ago(days=4).replace(hour=0), "privileged_command")
        self.assertEqual(len(rules.off_hours_privileged(c, P, AS_OF)), 1)


if __name__ == "__main__":
    unittest.main()
