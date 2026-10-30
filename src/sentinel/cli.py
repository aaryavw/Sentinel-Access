"""Command-line interface: generate -> ingest -> scan -> report -> evaluate -> serve."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from sentinel import __version__
from sentinel.auth import AuthConfigError, create_token
from sentinel.config import PolicyError, load_policy
from sentinel.db import connect, init_db
from sentinel.evaluate import evaluate
from sentinel.generator import generate
from sentinel.ingest import IngestError, ingest_directory
from sentinel.report import write_reports
from sentinel.scanner import run_scan
from sentinel.util import parse_ts, utcnow


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--policy", help="path to a policy JSON file overriding defaults")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="create synthetic CSV data")
    g.add_argument("--out", default="data/synthetic")
    g.add_argument("--seed", type=int, default=1337)
    g.add_argument("--users", type=int, default=120)
    g.add_argument("--clean", action="store_true", help="omit deliberately malformed rows")

    i = sub.add_parser("ingest", help="validate and load CSVs into SQLite")
    i.add_argument("--db", default="sentinel.db")
    i.add_argument("--data", default="data/synthetic")

    s = sub.add_parser("scan", help="run detection rules")
    s.add_argument("--db", default="sentinel.db")
    s.add_argument("--as-of", help="ISO-8601 reference time (default: now)")

    r = sub.add_parser("report", help="write report.json and report.md")
    r.add_argument("--db", default="sentinel.db")
    r.add_argument("--out", default="reports")

    e = sub.add_parser("evaluate", help="compare findings with generator ground truth")
    e.add_argument("--db", default="sentinel.db")
    e.add_argument("--truth", default="data/synthetic/ground_truth.json")

    t = sub.add_parser("token", help="create an API token (shown once)")
    t.add_argument("--tokens", default="tokens.json")
    t.add_argument("--name", required=True)
    t.add_argument("--role", required=True, choices=["viewer", "analyst", "admin"])

    v = sub.add_parser("serve", help="start the HTTP API")
    v.add_argument("--db", default="sentinel.db")
    v.add_argument("--tokens", default="tokens.json")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8080)

    d = sub.add_parser("demo", help="run the whole pipeline end to end")
    d.add_argument("--workdir", default="demo_out")
    return p


def _pipeline(policy, workdir: str) -> None:
    data_dir = os.path.join(workdir, "data")
    db_path = os.path.join(workdir, "sentinel.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    manifest = generate(data_dir)
    print(f"[generate] {manifest['users']} users, {manifest['events']} events -> {data_dir}")
    conn = connect(db_path)
    init_db(conn)
    for res in ingest_directory(conn, data_dir):
        print(f"[ingest]   {res.table}: read={res.read} loaded={res.loaded} quarantined={res.quarantined}")
    scan = run_scan(conn, policy, parse_ts(manifest["as_of"]))
    print(f"[scan]     {scan['total']} findings as of {scan['as_of']}: {scan['findings_by_rule']}")
    jpath, mpath = write_reports(conn, policy, os.path.join(workdir, "reports"))
    print(f"[report]   {jpath}, {mpath}")
    result = evaluate(conn, os.path.join(data_dir, "ground_truth.json"))
    for rule, st in result["per_rule"].items():
        print(f"[evaluate] {rule:22s} TP={st['true_positive']} FP={st['false_positive']} "
              f"FN={st['false_negative']} (synthetic scenarios only)")
    print(f"[evaluate] benign controls flagged: {result['benign_controls_flagged'] or 'none'}")
    conn.close()


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        policy = load_policy(args.policy)
        if args.cmd == "generate":
            m = generate(args.out, seed=args.seed, n_users=args.users, dirty=not args.clean)
            print(json.dumps(m, indent=2))
        elif args.cmd == "ingest":
            conn = connect(args.db)
            init_db(conn)
            for res in ingest_directory(conn, args.data):
                print(json.dumps(res.as_dict()))
        elif args.cmd == "scan":
            conn = connect(args.db)
            init_db(conn)
            as_of = parse_ts(args.as_of) if args.as_of else utcnow()
            print(json.dumps(run_scan(conn, policy, as_of), indent=2))
        elif args.cmd == "report":
            conn = connect(args.db)
            print("\n".join(write_reports(conn, policy, args.out)))
        elif args.cmd == "evaluate":
            conn = connect(args.db)
            print(json.dumps(evaluate(conn, args.truth), indent=2))
        elif args.cmd == "token":
            token = create_token(args.tokens, args.name, args.role)
            print(f"Token for {args.name} ({args.role}); store it now, it is not saved in clear:\n{token}")
        elif args.cmd == "serve":
            from sentinel.api import make_server
            server = make_server(args.db, args.tokens, policy, args.host, args.port)
            print(f"Serving on http://{args.host}:{server.server_address[1]} (Ctrl+C to stop)")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                server.server_close()
        elif args.cmd == "demo":
            _pipeline(policy, args.workdir)
        return 0
    except (PolicyError, IngestError, AuthConfigError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
