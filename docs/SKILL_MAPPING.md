# Skill-to-project mapping

The posting names mission areas rather than specific languages or frameworks, so
**Python** was chosen as a widely used language for security automation and data
work. That is an assumption, not a posting requirement. Priority below is
"stated" (named in the posting) or "inferred" (implied by the work described).

| Posting item | Priority | Where it is demonstrated | What it shows | Gap / limitation |
|---|---|---|---|---|
| Secure software development | stated | Validation in `ingest.py`; parameterised SQL everywhere; allow-listed filters and body cap in `api.py`; threat model in `docs/ARCHITECTURE.md`; security tests in `tests/test_api.py` | Designing for hostile input, writing tests that attack your own code | No third-party audit; plain HTTP |
| Identity and access management | stated | `rules.py` (SoD, orphaned, stale, unused privilege); `auth.py` (token hashing, RBAC) | Joiner/mover/leaver and least-privilege review logic; role enforcement | No real IdP / OIDC / MFA |
| Cybersecurity | stated | `impossible_travel`, `brute_force_success`, `off_hours_privileged`; audit log | Defensive detection and evidence-bearing findings | Thresholds untuned; no real-world data |
| Data pipelines | stated | `generator` → `ingest` (quarantine, idempotent upserts) → `scanner` → `report` | Validation, data-quality visibility, reproducible runs | Batch only; no streaming or scheduler |
| Analytics | stated | `scoring.py`, `report.py`, `evaluate.py` | Aggregation, explainable risk scoring, precision/recall harness | Evaluation is on injected synthetic scenarios only |
| DevSecOps | stated | `.github/workflows/ci.yml` (tests on 3 Python versions, Bandit, gitleaks), non-root `Dockerfile`, no dependencies | Security checks in the pipeline; minimal attack surface | CI and Docker files were **not executed** during the build |
| Cloud applications | stated | Containerisable service with health check and env-free config | Deployable-service shape | **Not deployed** to any cloud; no IaC |
| AI-enabled automation | stated | Automated triage workflow and risk ranking (rule-based) | Automation of first-pass review | **Gap:** no ML. A statistical-baseline rule is the proposed extension |
| Testing and documentation | inferred | 46 tests, README, architecture and this mapping | Engineering discipline | No coverage tool run |
| Clearance-readiness mindset | inferred | Synthetic-only data, no secrets, least privilege, auditability | Handling security-relevant work responsibly | A project cannot demonstrate clearance eligibility |
