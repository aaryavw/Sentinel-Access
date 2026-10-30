# Architecture

## Components (src/sentinel)

| Module | Responsibility |
|---|---|
| `generator.py` | Seeded synthetic data with injected anomalies, benign controls and deliberately bad rows; writes `ground_truth.json` |
| `ingest.py` | CSV validation and idempotent upserts; `quarantine` for rejects |
| `db.py` | Schema (CHECK constraints, FKs, indexes), connection helper |
| `rules.py` | Seven pure detection functions + `RULES` registry |
| `scanner.py` | Runs rules, upserts findings with deterministic IDs, preserves triage |
| `scoring.py` | Explainable risk scores and bands |
| `report.py` / `evaluate.py` | JSON/Markdown reports; ground-truth comparison |
| `auth.py` / `api.py` | Hashed bearer tokens, RBAC, HTTP routing, audit logging |
| `config.py` | Validated detection policy |
| `cli.py` | `generate`, `ingest`, `scan`, `report`, `evaluate`, `token`, `serve`, `demo` |

## Data model

`users(user_id PK, status, employment, termination_date, last_login, is_service)` ·
`entitlements(user_id, role) PK` · `access_events(event_id PK, ts, user_id, action, lat, lon, ...)` ·
`findings(finding_id PK = sha256(rule:user)[:16], severity, score, evidence JSON, status, triaged_by, ...)` ·
`audit_log` · `quarantine` · `meta`.

Timestamps are normalised to `YYYY-MM-DDTHH:MM:SSZ` at ingest so string comparison orders correctly.

## Detection rules

| Rule | Logic | Severity |
|---|---|---|
| stale_account | enabled, employed, non-service user with last login older than `stale_days` or never | medium; high if privileged |
| orphaned_account | terminated employee; any successful event after termination, or account still enabled | critical / high |
| separation_of_duties | holds both roles of any `toxic_role_pairs` entry | high |
| unused_privilege | privileged role, no `privileged_command` within `unused_privilege_days` | medium |
| impossible_travel | consecutive logins ≥ 500 km apart implying > 900 km/h (haversine) | high |
| brute_force_success | ≥ 5 failed logins within 10 minutes before a success (binary search over sorted failures) | high; critical if privileged |
| off_hours_privileged | ≥ 3 privileged commands outside business hours in 30 days; service accounts excluded | medium; high at ≥ 10 |

## Threat model (of the tool itself)

| Threat | Mitigation | Test |
|---|---|---|
| Unauthenticated access | Bearer token on all but `/health` | `test_missing_and_bad_tokens_get_401` |
| Privilege escalation | Per-route minimum role | `test_viewer_can_read_but_not_triage_or_scan` |
| SQL injection | Parameterised SQL; allow-listed filters; ID regexes | `test_sql_injection_attempts_are_inert` |
| Malicious input files | Per-field validation, length caps, quarantine | `test_hostile_identifiers_are_rejected` |
| Token theft from disk | Only hashes stored; file mode 0600 | `test_tokens_stored_hashed_with_private_permissions` |
| Timing attacks on token check | `hmac.compare_digest`, no early exit | (design; not separately tested) |
| Repudiation | Audit log of allowed and denied requests | `test_admin_scan_and_audit_trail` |
| Resource exhaustion | 16 KB body cap, `limit` clamped | `test_oversized_body_rejected` |
| Markdown injection via data | `md_escape` in reports | `test_markdown_escape` |
| Information leakage | Generic 500s; Python version string suppressed | (design; not separately tested) |
