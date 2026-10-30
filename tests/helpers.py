"""Shared test helpers: tiny in-memory fixtures and a generated demo database."""
import os
import tempfile
from datetime import datetime, timedelta, timezone

from sentinel.db import connect, init_db
from sentinel.generator import generate
from sentinel.ingest import ingest_directory
from sentinel.util import fmt_ts

AS_OF = datetime(2026, 10, 1, tzinfo=timezone.utc)


def mem_db():
    conn = connect(":memory:")
    init_db(conn)
    return conn


def add_user(conn, uid, status="active", employment="employed", term=None,
             last_login=None, service=0, roles=()):
    conn.execute(
        "INSERT INTO users VALUES(?,?,?,?,?,?,?,?)",
        (uid, "name_" + uid, "Dept", status, employment, term, last_login, service))
    for r in roles:
        conn.execute("INSERT INTO entitlements VALUES(?,?,?)", (uid, r, "2020-01-01T00:00:00Z"))
    conn.commit()


_counter = [0]


def add_event(conn, uid, ts, action="login", lat=38.33, lon=-77.04, country="US"):
    _counter[0] += 1
    conn.execute(
        "INSERT INTO access_events VALUES(?,?,?,?,?,?,?,?,?)",
        (f"ev{_counter[0]:06d}", fmt_ts(ts) if isinstance(ts, datetime) else ts, uid, action,
         "r", "192.0.2.1", country, lat, lon))
    conn.commit()


def ago(**kw):
    return AS_OF - timedelta(**kw)


def build_demo_db(directory, n_users=120):
    """Generate synthetic data, ingest it, and return (conn, manifest, data_dir)."""
    data_dir = os.path.join(directory, "data")
    manifest = generate(data_dir, n_users=n_users)
    conn = connect(os.path.join(directory, "demo.db"))
    init_db(conn)
    ingest_directory(conn, data_dir)
    return conn, manifest, data_dir


def tmpdir():
    return tempfile.TemporaryDirectory()
