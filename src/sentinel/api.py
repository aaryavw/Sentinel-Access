"""Minimal JSON HTTP API (standard library only).

Security properties:
  * every route except /health requires a bearer token
  * role-based access control (viewer < analyst < admin), enforced per route
  * every authenticated or rejected request is written to the audit log
  * all SQL is parameterised; filters are validated against allow-lists
  * request bodies are size-limited; errors never leak internals
  * binds to loopback by default; no CORS; no caching of responses
"""
from __future__ import annotations

import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sentinel.auth import TokenStore, parse_bearer
from sentinel.config import SEVERITIES, Policy
from sentinel.db import connect, get_meta, init_db
from sentinel.scanner import run_scan
from sentinel.scoring import top_risk, user_risk
from sentinel.util import fmt_ts, parse_ts, utcnow

log = logging.getLogger("sentinel.http")
MAX_BODY = 16 * 1024
STATUSES = ("open", "confirmed", "false_positive", "resolved")
ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _int(query, key, default, lo, hi):
    if key not in query:
        return default
    try:
        value = int(query[key][0])
    except ValueError:
        raise ApiError(400, f"{key} must be an integer") from None
    return max(lo, min(hi, value))


def _row_to_finding(row) -> dict:
    d = dict(row)
    d["evidence"] = json.loads(d["evidence"])
    return d


# ---- route handlers: (ctx, match, query, body) -> (status, payload) -------

def h_health(ctx, m, q, body):
    return 200, {"status": "ok"}


def h_findings(ctx, m, q, body):
    where, params = [], []
    allowed = {"severity": SEVERITIES, "status": STATUSES}
    for key in ("severity", "status", "rule_id", "user_id"):
        if key in q:
            value = q[key][0]
            if key in allowed and value not in allowed[key]:
                raise ApiError(400, f"invalid {key}")
            if key in ("rule_id", "user_id") and not ID_RE.match(value):
                raise ApiError(400, f"invalid {key}")
            where.append(f"{key} = ?")  # key comes from the fixed tuple above
            params.append(value)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    limit = _int(q, "limit", 50, 1, 200)
    offset = _int(q, "offset", 0, 0, 10_000_000)
    # nosec B608: `clause` is assembled only from the fixed column tuple above; values are bound.
    total = ctx.conn.execute(f"SELECT COUNT(*) FROM findings{clause}", params).fetchone()[0]  # nosec B608
    rows = ctx.conn.execute(  # nosec B608
        f"SELECT * FROM findings{clause} ORDER BY CASE severity WHEN 'critical' THEN 0 "
        "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, user_id, finding_id "
        "LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
    return 200, {"total": total, "limit": limit, "offset": offset,
                 "items": [_row_to_finding(r) for r in rows]}


def h_finding(ctx, m, q, body):
    row = ctx.conn.execute("SELECT * FROM findings WHERE finding_id = ?", (m.group(1),)).fetchone()
    if row is None:
        raise ApiError(404, "finding not found")
    return 200, _row_to_finding(row)


def h_triage(ctx, m, q, body):
    status = body.get("status")
    note = body.get("note", "")
    if status not in STATUSES:
        raise ApiError(400, f"status must be one of {list(STATUSES)}")
    if not isinstance(note, str) or len(note) > 500:
        raise ApiError(400, "note must be a string of at most 500 characters")
    cur = ctx.conn.execute(
        "UPDATE findings SET status = ?, triage_note = ?, triaged_by = ?, updated_at = ? "
        "WHERE finding_id = ?", (status, note, ctx.principal.name, fmt_ts(utcnow()), m.group(1)))
    ctx.conn.commit()
    if cur.rowcount == 0:
        raise ApiError(404, "finding not found")
    return h_finding(ctx, m, q, body)


def h_user_risk(ctx, m, q, body):
    profile = user_risk(ctx.conn, ctx.policy, m.group(1))
    if profile is None:
        raise ApiError(404, "user not found")
    return 200, profile


def h_top_risk(ctx, m, q, body):
    return 200, {"items": top_risk(ctx.conn, ctx.policy, _int(q, "limit", 10, 1, 100))}


def h_scan(ctx, m, q, body):
    raw = body.get("as_of")
    try:
        if raw is not None:
            as_of = parse_ts(raw)
        else:
            previous = get_meta(ctx.conn, "last_as_of")
            as_of = parse_ts(previous) if previous else utcnow()
    except (ValueError, TypeError):
        raise ApiError(400, "as_of must be an ISO-8601 timestamp") from None
    return 200, run_scan(ctx.conn, ctx.policy, as_of)


def h_audit(ctx, m, q, body):
    limit = _int(q, "limit", 100, 1, 500)
    rows = ctx.conn.execute(
        "SELECT id, ts, actor, action, target, outcome FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,)).fetchall()
    return 200, {"items": [dict(r) for r in rows]}


# method, pattern, minimum role (None = public), handler
ROUTES = [
    ("GET", re.compile(r"^/health$"), None, h_health),
    ("GET", re.compile(r"^/findings$"), "viewer", h_findings),
    ("GET", re.compile(r"^/findings/([0-9a-f]{16})$"), "viewer", h_finding),
    ("POST", re.compile(r"^/findings/([0-9a-f]{16})/triage$"), "analyst", h_triage),
    ("GET", re.compile(r"^/users/([A-Za-z0-9_.\-]{1,64})/risk$"), "viewer", h_user_risk),
    ("GET", re.compile(r"^/risk/top$"), "viewer", h_top_risk),
    ("POST", re.compile(r"^/scan$"), "admin", h_scan),
    ("GET", re.compile(r"^/audit$"), "admin", h_audit),
]


class _Ctx:
    def __init__(self, conn, policy, principal):
        self.conn, self.policy, self.principal = conn, policy, principal


class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelAccess"
    sys_version = ""

    def log_message(self, fmt, *args):  # route access logs through logging
        log.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status, payload, headers=None):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        length_raw = self.headers.get("Content-Length")
        if length_raw is None:
            return {}
        try:
            length = int(length_raw)
        except ValueError:
            raise ApiError(400, "invalid Content-Length") from None
        if length < 0:
            raise ApiError(400, "invalid Content-Length")
        if length > MAX_BODY:
            raise ApiError(413, "request body too large")
        if length == 0:
            return {}
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "body must be valid JSON") from None
        if not isinstance(body, dict):
            raise ApiError(400, "body must be a JSON object")
        return body

    def _audit(self, conn, actor, action, target, outcome):
        conn.execute("INSERT INTO audit_log(ts, actor, action, target, outcome) VALUES(?,?,?,?,?)",
                     (fmt_ts(utcnow()), actor, action, target[:200], outcome))
        conn.commit()

    def _dispatch(self, method):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        conn = None
        try:
            conn = connect(self.server.db_path)
            route = next(((r, m) for r in ROUTES if r[0] == method
                          for m in [r[1].match(parts.path)] if m), None)
            if route is None:
                known = any(r[1].match(parts.path) for r in ROUTES)
                raise ApiError(405 if known else 404, "method not allowed" if known else "not found")
            (_, pattern, min_role, handler), match = route
            principal = None
            if min_role is not None:
                token = parse_bearer(self.headers.get("Authorization"))
                principal = self.server.tokens.authenticate(token) if token else None
                label = f"{method} {pattern.pattern}"
                if principal is None:
                    self._audit(conn, "anonymous", label, parts.path, "denied:unauthenticated")
                    raise ApiError(401, "authentication required")
                if not principal.allows(min_role):
                    self._audit(conn, principal.name, label, parts.path, "denied:forbidden")
                    raise ApiError(403, "insufficient role")
            body = self._body() if method == "POST" else {}
            status, payload = handler(_Ctx(conn, self.server.policy, principal), match, query, body)
            if principal is not None:
                self._audit(conn, principal.name, f"{method} {pattern.pattern}", parts.path, f"ok:{status}")
            self._send(status, payload,
                       {"WWW-Authenticate": "Bearer"} if status == 401 else None)
        except ApiError as exc:
            self._send(exc.status, {"error": exc.message},
                       {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None)
        except Exception:  # never leak internals to clients
            log.exception("unhandled error for %s %s", method, parts.path)
            self._send(500, {"error": "internal error"})
        finally:
            if conn is not None:
                conn.close()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._send(405, {"error": "method not allowed"})

    do_DELETE = do_PATCH = do_PUT


def make_server(db_path: str, tokens_path: str, policy: Policy,
                host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    conn = connect(db_path)
    init_db(conn)
    conn.close()
    server = ThreadingHTTPServer((host, port), Handler)
    server.db_path, server.tokens, server.policy = db_path, TokenStore(tokens_path), policy
    server.daemon_threads = True
    return server
