# Interview guide

## 30-second pitch

"I built SentinelAccess, a pipeline that reviews who has access to what. It
ingests account, role and login data, quarantines malformed rows, and runs seven
detections: dormant accounts, terminated employees who still have access,
conflicting roles, unused admin rights, impossible travel, brute-force-then-
success, and off-hours admin activity. Findings get a score and are exposed
through an API with token authentication, role-based access control and an audit
log. It uses synthetic data and only the Python standard library, and the test
suite includes attacks against my own API such as injection strings and
privilege-escalation attempts."

## Walkthrough order for a live demo

1. `python -m sentinel demo --workdir demo_out` and read the output (quarantine counts, findings per rule).
2. Open `docs/sample_report.md`.
3. Start the API, call `/risk/top`, then try a viewer token on `/scan` to show the 403 and the audit entry.

## The most interesting parts (plain language)

- **Impossible travel** (`rules.py`): for each user, sort logins by time, compute great-circle distance between consecutive ones, divide by elapsed hours. If it implies faster than a jet, flag it. Elapsed time is floored at one second so identical timestamps cannot divide by zero.
- **Brute force** (`rules.py`): failures are kept in a sorted list; for each success, two binary searches count failures in the preceding 10 minutes. That is O(n log n) rather than rescanning for every success.
- **Stable finding IDs** (`scanner.py`): `sha256(rule:user)`; upserts update evidence but never touch `status`, so re-scans do not erase analyst decisions.
- **Quarantine** (`ingest.py`): one bad row never blocks a load, and nothing is silently discarded.
- **Token handling** (`auth.py`): only hashes at rest, constant-time compare, role rank check per route.

## Likely questions

**1. Why Python standard library only?**
Smaller supply-chain surface and zero setup. The trade-off is a hand-written router and no TLS; in production I would use a framework behind a TLS-terminating proxy.

**2. How do you prevent SQL injection?**
Every value is bound as a parameter. The only dynamic SQL is a WHERE clause assembled from a fixed tuple of column names, and filter values are validated against allow-lists or an ID regex. A test sends injection strings and asserts 400/404 and an intact database.

**3. Why store a SHA-256 hash of the token rather than bcrypt?**
Tokens are 256 random bits, not human-chosen passwords, so brute-forcing a leaked hash is infeasible and slow hashing adds nothing. For human passwords I would use a memory-hard KDF such as scrypt or Argon2.

**4. A rule fires on a legitimate user. What happens?**
An analyst triages it as `false_positive`. That status survives re-scans (the finding ID is stable) and removes the finding from the user's risk score. The audit log records who decided.

**5. How would you know the detections are any good?**
On this project I only know the rules catch scenarios I injected, which is a regression test, not accuracy. For real accuracy I would label a sample of real findings and compute precision and recall per rule, then tune thresholds.

**6. What breaks at scale?**
SQLite and synchronous scans. Events would move to a columnar store or Postgres, per-user rules would run incrementally by time window, and `/scan` would become a background job.

**7. Why is service-account activity excluded from some rules?**
Batch jobs legitimately run at night and never "log in" interactively. Including them would flood off-hours and stale checks. They need their own controls (credential rotation, ownership), noted as future work. A test asserts the exclusion.

**8. What is separation of duties and why does it matter?**
One person should not hold two roles that together allow fraud or bypass of control, such as requesting and approving the same payment. The policy lists conflicting pairs and the rule flags anyone holding both.

**9. How does RBAC work here?**
Each route declares a minimum role; `viewer < analyst < admin`. The check happens before the handler runs and both denials and successes are written to the audit log.

**10. What would you add to make it "AI-enabled"?**
A per-user baseline (for example robust z-score on daily export volume) producing an explainable anomaly score alongside the rules. I would keep it explainable and measured against labelled data before trusting it.

## Be honest about

- It is a portfolio project on synthetic data; never describe it as deployed or used operationally.
- CI and Docker files exist but you should run them yourself before claiming they work.
- Only say "I built" about parts you have read, run and can explain; modify at least one rule or add a test yourself before the interview so the code is genuinely yours to discuss.
- The posting does not name languages; Python was your choice, and you can say why.
