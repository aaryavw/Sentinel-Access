# SentinelAccess

An identity-and-access risk analytics pipeline with a role-protected REST API.
It ingests account, entitlement and access-event data, validates it, detects
risky access patterns, scores users, and lets analysts triage findings through
an audited API.

> **Synthetic data only.** Every user, IP address and event here is fabricated by
> `generator.py`. Nothing in this repository represents a real person, system or
> network. This is a defensive, educational portfolio project.

Built for a Summer 2027 internship application whose mission areas include secure
software development, data pipelines, analytics, identity and access management,
cybersecurity and DevSecOps. It is an independent project and is not affiliated
with, endorsed by, or derived from any government system.

## Problem

Organisations accumulate access they no longer need: accounts of departed staff,
dormant privileged accounts, people who can both request and approve the same
action, logins that could not have been made by one person. Reviewing this by
hand does not scale. SentinelAccess automates the first pass and produces
explainable, triage-able findings for a human analyst.

## Features

| Capability | Detail |
|---|---|
| Validating ingest | Row-level validation; bad rows go to a `quarantine` table with a reason instead of being dropped or aborting the load. Idempotent. |
| 7 detection rules | stale account, orphaned (terminated) account, separation-of-duties conflict, unused privilege, impossible travel, brute-force-then-success, off-hours privileged activity |
| Explainable scoring | Per-user risk = sum of severity points of *active* findings, capped at 100. Triage changes the ranking. |
| Stable findings | One finding per (rule, user) with a deterministic ID; re-scans never duplicate or erase analyst decisions. |
| Secure API | Bearer tokens (stored hashed), RBAC (`viewer` < `analyst` < `admin`), audit log of every request, parameterised SQL, allow-listed filters, body-size limit, no internals in errors. |
| Policy as config | Thresholds and toxic role pairs live in a validated policy object; unknown keys are rejected. |
| Evaluation harness | Compares detections to the generator's injected ground truth (a regression check, not a real-world accuracy claim). |
| Zero runtime dependencies | Python standard library only (3.10+). |

## Architecture

```
 generator ──CSV──▶ ingest ──▶ SQLite ──▶ rules ──▶ findings ──▶ scoring ──▶ report (JSON/MD)
 (synthetic)       (validate,  users          │          ▲                      │
                    quarantine) entitlements  │          │ triage               ▼
                               access_events  └──────────┼──────────────── REST API (auth + RBAC + audit)
                               quarantine, audit_log     └── analysts
```

Details and the threat model are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

Prerequisite: Python 3.10 or newer. No `pip install` needed.

```bash
git clone <your-repo-url> sentinel-access && cd sentinel-access
export PYTHONPATH=src            # Windows PowerShell: $env:PYTHONPATH="src"

python -m sentinel demo --workdir demo_out
```

This generates data, ingests it (quarantining the deliberately malformed rows),
scans, writes `demo_out/reports/report.{json,md}` and prints an evaluation
against the injected scenarios. See [docs/sample_report.md](docs/sample_report.md).

### Run the API

```bash
python -m sentinel token --tokens tokens.json --name alice --role admin   # prints token once
python -m sentinel serve --db demo_out/sentinel.db --tokens tokens.json --port 8080
```

```bash
TOKEN=<paste token>
curl localhost:8080/health
curl -H "Authorization: Bearer $TOKEN" "localhost:8080/risk/top?limit=3"
curl -H "Authorization: Bearer $TOKEN" "localhost:8080/findings?severity=critical"
curl -X POST -H "Authorization: Bearer $TOKEN" -d '{"status":"confirmed","note":"verified with HR"}' \
     localhost:8080/findings/<finding_id>/triage
curl -H "Authorization: Bearer $TOKEN" localhost:8080/audit
```

| Method & path | Min. role | Purpose |
|---|---|---|
| `GET /health` | none | liveness |
| `GET /findings?severity=&status=&rule_id=&user_id=&limit=&offset=` | viewer | list/filter findings |
| `GET /findings/{id}` | viewer | one finding with evidence |
| `POST /findings/{id}/triage` | analyst | set status (`open`, `confirmed`, `false_positive`, `resolved`) + note |
| `GET /users/{user_id}/risk` | viewer | risk profile |
| `GET /risk/top?limit=` | viewer | highest-risk users |
| `POST /scan` | admin | re-run rules; optional `{"as_of": "..."}` (defaults to the previous scan's reference time) |
| `GET /audit?limit=` | admin | audit trail |

### Step-by-step CLI

```bash
python -m sentinel generate --out data/synthetic
python -m sentinel ingest   --db sentinel.db --data data/synthetic
python -m sentinel scan     --db sentinel.db --as-of 2026-10-01T00:00:00Z
python -m sentinel report   --db sentinel.db --out reports
python -m sentinel evaluate --db sentinel.db --truth data/synthetic/ground_truth.json
```

Use `--policy config/policy.json` (before the sub-command) to override thresholds.

## Tests

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -v     # or: make test
```

46 tests cover rule boundaries (e.g. exactly 90 days vs 90 days + 1 second),
ingest validation, scoring, report escaping, policy validation, token handling,
and the HTTP API (401/403/404/405/413, SQL-injection attempts, triage
persistence, audit trail).

## Configuration

Defaults are in `sentinel/config.py`; `config/policy.json` shows an override.
Tokens are never stored in clear: only SHA-256 digests are written to
`tokens.json` (mode 0600, git-ignored). No secrets are needed or committed.

## Design decisions and trade-offs

- **Standard library only.** Zero supply-chain surface and runs anywhere; the cost is a hand-rolled router. For production I would use a mature framework, a real IdP (OIDC) and TLS termination.
- **One finding per (rule, user).** Keeps IDs stable and triage durable; individual events live in `evidence`.
- **Quarantine, don't crash.** Bad data is a normal operating condition; visibility matters more than purity.
- **Rules as pure functions of (DB, policy, time).** Time is injected (`as_of`), so every result is reproducible and testable.
- **Rules before ML.** Rule output is explainable, which is what access reviewers need. A statistical baseline is listed under future work.

## Security considerations and known limitations

- Plain HTTP; run behind a TLS-terminating proxy. No rate limiting or token expiry/rotation.
- Bearer tokens are static; revocation means editing the token file and restarting.
- `POST /scan` runs synchronously in the request thread; a large dataset would need a background worker.
- Findings that stop being true are not auto-closed on re-scan (analysts resolve them).
- Impossible-travel ignores VPN/proxy egress; thresholds are illustrative, not tuned.
- Evaluation results are against injected synthetic scenarios, so perfect recall there says nothing about real-world accuracy. Measure real accuracy by labelling a sample of findings from a real data source and computing precision/recall.
- Dockerfile and GitHub Actions workflow are provided but were not executed when this project was built (see the validation report in the delivery message).

## Future improvements

1. Per-user statistical baselines (e.g. robust z-score on export volume) as an explainable "AI-assisted" rule.
2. Token expiry and rotation; OIDC integration.
3. Auto-close findings that no longer reproduce; scheduled scans.
4. Postgres backend and a small dashboard.
