import json
import os
import threading
import unittest
import urllib.error
import urllib.request

from helpers import AS_OF, build_demo_db, tmpdir
from sentinel.api import make_server
from sentinel.auth import AuthConfigError, TokenStore, create_token, parse_bearer
from sentinel.config import load_policy
from sentinel.scanner import run_scan


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tmpdir()
        d = cls._tmp.name
        conn, _, _ = build_demo_db(d)
        policy = load_policy()
        run_scan(conn, policy, AS_OF)
        conn.close()
        cls.tokens_path = os.path.join(d, "tokens.json")
        cls.tok = {role: create_token(cls.tokens_path, role, role) for role in ("viewer", "analyst", "admin")}
        cls.server = make_server(os.path.join(d, "demo.db"), cls.tokens_path, policy, port=0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmp.cleanup()

    def call(self, method, path, token=None, body=None, raw=None, headers=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read()), resp.headers
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read()), err.headers

    # ---- authentication ----
    def test_health_is_public(self):
        status, body, _ = self.call("GET", "/health")
        self.assertEqual((status, body), (200, {"status": "ok"}))

    def test_missing_and_bad_tokens_get_401(self):
        for token in (None, "wrong", "x" * 300):
            status, _, headers = self.call("GET", "/findings", token=token)
            self.assertEqual(status, 401)
            self.assertEqual(headers["WWW-Authenticate"], "Bearer")

    def test_basic_auth_scheme_rejected(self):
        status, _, _ = self.call("GET", "/findings", headers={"Authorization": "Basic abc"})
        self.assertEqual(status, 401)

    # ---- authorization (RBAC) ----
    def test_viewer_can_read_but_not_triage_or_scan(self):
        v = self.tok["viewer"]
        status, body, hdr = self.call("GET", "/findings?limit=5", v)
        self.assertEqual(status, 200)
        self.assertEqual(hdr["Cache-Control"], "no-store")
        fid = body["items"][0]["finding_id"]
        self.assertEqual(self.call("POST", f"/findings/{fid}/triage", v, {"status": "resolved"})[0], 403)
        self.assertEqual(self.call("POST", "/scan", v, {})[0], 403)
        self.assertEqual(self.call("GET", "/audit", v)[0], 403)

    def test_analyst_triage_persists_with_attribution(self):
        a = self.tok["analyst"]
        _, body, _ = self.call("GET", "/findings?rule_id=stale_account&limit=1", a)
        fid = body["items"][0]["finding_id"]
        status, updated, _ = self.call("POST", f"/findings/{fid}/triage", a,
                                       {"status": "confirmed", "note": "verified with HR"})
        self.assertEqual(status, 200)
        self.assertEqual((updated["status"], updated["triaged_by"]), ("confirmed", "analyst"))
        _, again, _ = self.call("GET", f"/findings/{fid}", a)
        self.assertEqual(again["triage_note"], "verified with HR")
        self.assertEqual(self.call("POST", "/scan", a, {})[0], 403)

    def test_admin_scan_and_audit_trail(self):
        ad = self.tok["admin"]
        status, scan, _ = self.call("POST", "/scan", ad, {})
        self.assertEqual(status, 200)
        self.assertEqual(scan["as_of"], "2026-10-01T00:00:00Z")   # reuses the previous reference time
        self.call("GET", "/findings", self.tok["viewer"])
        self.call("POST", "/scan", self.tok["viewer"], {})
        status, audit, _ = self.call("GET", "/audit?limit=200", ad)
        self.assertEqual(status, 200)
        outcomes = {(i["actor"], i["outcome"]) for i in audit["items"]}
        self.assertIn(("viewer", "denied:forbidden"), outcomes)
        self.assertIn(("viewer", "ok:200"), outcomes)
        self.assertIn(("admin", "ok:200"), outcomes)

    def test_unauthenticated_attempts_are_audited(self):
        self.call("GET", "/findings", "bogus-token")
        _, audit, _ = self.call("GET", "/audit?limit=50", self.tok["admin"])
        self.assertIn("denied:unauthenticated", {i["outcome"] for i in audit["items"]})

    # ---- input validation / injection ----
    def test_sql_injection_attempts_are_inert(self):
        v = self.tok["viewer"]
        status, body, _ = self.call("GET", "/findings?user_id=%27%20OR%20%271%27%3D%271", v)
        self.assertEqual(status, 400)
        status, body, _ = self.call("GET", "/findings?severity=high%27%20OR%201%3D1--", v)
        self.assertEqual(status, 400)
        status, _, _ = self.call("GET", "/users/u0001%27%20OR%201=1/risk", v)
        self.assertEqual(status, 404)
        self.assertEqual(self.call("GET", "/findings?limit=1", v)[0], 200)   # DB intact

    def test_filters_and_pagination(self):
        v = self.tok["viewer"]
        _, body, _ = self.call("GET", "/findings?severity=critical", v)
        self.assertTrue(all(i["severity"] == "critical" for i in body["items"]))
        _, page1, _ = self.call("GET", "/findings?limit=3&offset=0", v)
        _, page2, _ = self.call("GET", "/findings?limit=3&offset=3", v)
        self.assertEqual(len(page1["items"]), 3)
        self.assertFalse({i["finding_id"] for i in page1["items"]} & {i["finding_id"] for i in page2["items"]})
        self.assertEqual(self.call("GET", "/findings?limit=abc", v)[0], 400)

    def test_triage_validation(self):
        a = self.tok["analyst"]
        _, body, _ = self.call("GET", "/findings?limit=1", a)
        fid = body["items"][0]["finding_id"]
        self.assertEqual(self.call("POST", f"/findings/{fid}/triage", a, {"status": "bogus"})[0], 400)
        self.assertEqual(self.call("POST", f"/findings/{fid}/triage", a, {"status": "open", "note": "x" * 501})[0], 400)
        self.assertEqual(self.call("POST", f"/findings/{fid}/triage", a, raw=b"{not json")[0], 400)
        self.assertEqual(self.call("POST", f"/findings/{fid}/triage", a, raw=b"[1,2]")[0], 400)
        self.assertEqual(self.call("POST", "/findings/0123456789abcdef/triage", a, {"status": "open"})[0], 404)

    def test_oversized_body_rejected(self):
        status, body, _ = self.call("POST", "/scan", self.tok["admin"], raw=b"{" + b" " * 20000 + b"}")
        self.assertEqual(status, 413)

    def test_routing_errors(self):
        v = self.tok["viewer"]
        self.assertEqual(self.call("GET", "/nope", v)[0], 404)
        self.assertEqual(self.call("DELETE", "/findings", v)[0], 405)
        self.assertEqual(self.call("POST", "/health")[0], 405)
        status, body, _ = self.call("GET", "/users/u0027/risk", v)
        self.assertEqual(status, 200)
        self.assertIn("risk_score", body)
        self.assertEqual(self.call("GET", "/risk/top?limit=3", v)[1]["items"].__len__(), 3)

    def test_bad_as_of_rejected(self):
        self.assertEqual(self.call("POST", "/scan", self.tok["admin"], {"as_of": "yesterday-ish"})[0], 400)


class AuthUnitTests(unittest.TestCase):
    def test_tokens_stored_hashed_with_private_permissions(self):
        with tmpdir() as d:
            path = os.path.join(d, "t.json")
            token = create_token(path, "alice", "analyst")
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn(token, fh.read())
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
            store = TokenStore(path)
            self.assertEqual(store.authenticate(token).role, "analyst")
            self.assertIsNone(store.authenticate(token + "x"))

    def test_duplicate_and_invalid_inputs(self):
        with tmpdir() as d:
            path = os.path.join(d, "t.json")
            create_token(path, "bob", "viewer")
            with self.assertRaises(AuthConfigError):
                create_token(path, "bob", "admin")
            with self.assertRaises(AuthConfigError):
                create_token(path, "eve", "root")
            with self.assertRaises(AuthConfigError):
                create_token(path, "bad name!", "viewer")

    def test_parse_bearer(self):
        self.assertEqual(parse_bearer("Bearer abc"), "abc")
        self.assertEqual(parse_bearer("bearer abc"), "abc")
        for bad in (None, "", "Bearer", "Token abc", "Bearer " + "a" * 300):
            self.assertIsNone(parse_bearer(bad))


if __name__ == "__main__":
    unittest.main()
