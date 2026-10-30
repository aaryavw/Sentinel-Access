# SentinelAccess Report

Reference time (as-of): `2026-10-01T00:00:00Z`

> Synthetic data only. Findings are leads for human review, not verdicts.

## Summary

Total findings: **23**

| Severity | Count |
|---|---|
| critical | 2 |
| high | 11 |
| medium | 10 |
| low | 0 |

| Rule | Count |
|---|---|
| brute\_force\_success | 3 |
| impossible\_travel | 3 |
| off\_hours\_privileged | 3 |
| orphaned\_account | 3 |
| separation\_of\_duties | 4 |
| stale\_account | 4 |
| unused\_privilege | 3 |

## Data quality

- access\_events.csv: 6 row(s) quarantined
- entitlements.csv: 1 row(s) quarantined
- users.csv: 1 row(s) quarantined

## Highest-risk users

| User | Dept | Risk | Band | Rules |
|---|---|---|---|---|
| user0027 | Security | 40 | high | orphaned\_account |
| user0031 | Engineering | 40 | high | orphaned\_account |
| user0006 | Analytics | 25 | high | brute\_force\_success |
| user0009 | Security | 25 | high | separation\_of\_duties |
| user0029 | HR | 25 | high | orphaned\_account |
| user0036 | Analytics | 25 | high | separation\_of\_duties |
| user0040 | Finance | 25 | high | separation\_of\_duties |
| user0051 | Security | 25 | high | brute\_force\_success |
| user0052 | Finance | 25 | high | brute\_force\_success |
| user0062 | Operations | 25 | high | separation\_of\_duties |

## Findings

- **CRITICAL** `f0c3816f8af4039c` Activity after termination - user0027 was terminated 2026-09-01T00:00:00Z but 21 successful events occurred afterwards. _(status: open)_
- **CRITICAL** `0e74685710d3c410` Activity after termination - user0031 was terminated 2026-09-01T00:00:00Z but 19 successful events occurred afterwards. _(status: open)_
- **HIGH** `35e30c59451f2c5b` Successful login after burst of failures - user0006: 7 failed logins within 10 min preceded a success. _(status: open)_
- **HIGH** `74f7c792657aa447` Conflicting roles held by one user - user0009 holds conflicting roles: approver + requester. _(status: open)_
- **HIGH** `c2c8fae8a8218d3a` Terminated employee account still enabled - user0029 was terminated 2026-09-01T00:00:00Z but the account remains enabled. _(status: open)_
- **HIGH** `e0e36b0e0691239b` Conflicting roles held by one user - user0036 holds conflicting roles: approver + requester. _(status: open)_
- **HIGH** `62acfd256e3413d2` Conflicting roles held by one user - user0040 holds conflicting roles: approver + requester. _(status: open)_
- **HIGH** `9902818bc2823c04` Successful login after burst of failures - user0051: 7 failed logins within 10 min preceded a success. _(status: open)_
- **HIGH** `7391865906a0b684` Successful login after burst of failures - user0052: 7 failed logins within 10 min preceded a success. _(status: open)_
- **HIGH** `8e27f40d55299b39` Conflicting roles held by one user - user0062 holds conflicting roles: auditor + db\_admin. _(status: open)_
- **HIGH** `70bfdddf6fbca4fb` Impossible travel between logins - user0066: 2 login pair(s) imply travel above 900 km/h (worst 15767 km in 2026-09-21T15:00:00Z -\> 2026-09-21T15:30:00Z). _(status: open)_
- **HIGH** `24a37d1e069aed08` Impossible travel between logins - user0073: 2 login pair(s) imply travel above 900 km/h (worst 7631 km in 2026-09-21T15:00:00Z -\> 2026-09-21T15:30:00Z). _(status: open)_
- **HIGH** `2d2ae01d43e28155` Impossible travel between logins - user0120: 1 login pair(s) imply travel above 900 km/h (worst 7612 km in 2026-09-21T15:00:00Z -\> 2026-09-21T15:30:00Z). _(status: open)_
- **MEDIUM** `150def25549f309f` Privileged role not exercised recently - user0002 holds db\_admin but ran no privileged command in 60 days. Consider revoking. _(status: open)_
- **MEDIUM** `1da0e905f7cfd68d` Enabled account with no recent login - user0005 has never logged in (policy: 90 days). _(status: open)_
- **MEDIUM** `991f6ac9f6091976` Privileged role not exercised recently - user0026 holds prod\_deployer but ran no privileged command in 60 days. Consider revoking. _(status: open)_
- **MEDIUM** `f92f9be8fd2f1cdb` Privileged role not exercised recently - user0069 holds security\_admin but ran no privileged command in 60 days. Consider revoking. _(status: open)_
- **MEDIUM** `2ecfc70cd8f89637` Enabled account with no recent login - user0076 has never logged in (policy: 90 days). _(status: open)_
- **MEDIUM** `a3bc81f49949415a` Enabled account with no recent login - user0082 has never logged in (policy: 90 days). _(status: open)_
- **MEDIUM** `38053ac353e15d53` Privileged activity outside business hours - user0092 ran 6 privileged commands outside 12:00-22:00 UTC in the last 30 days. _(status: open)_
- **MEDIUM** `b3bc416d7704860e` Enabled account with no recent login - user0103 has never logged in (policy: 90 days). _(status: open)_
- **MEDIUM** `d30a7aab058aff7e` Privileged activity outside business hours - user0111 ran 5 privileged commands outside 12:00-22:00 UTC in the last 30 days. _(status: open)_
- **MEDIUM** `9db8a3863cfcf706` Privileged activity outside business hours - user0116 ran 5 privileged commands outside 12:00-22:00 UTC in the last 30 days. _(status: open)_
