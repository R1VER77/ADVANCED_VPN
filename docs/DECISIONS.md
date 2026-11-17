# Decision log

Decisions can be reopened through an issue or pull request with new evidence.
The maintainer is responsible for the decisions below. They are project decisions,
not independent review findings.

| ID / date | Decision and reason | Evidence and acceptance / revisit condition |
|---|---|---|
| D001 / 2026-11-17 | Keep relay look-ahead defaults unchanged and wire-clock controls experimental. The 5 ms arm improved load success but missed more slots; classification remained above nominal chance. | [400-load analysis](WF_REAL_RERUN3.md). Revisit after fresh-control, counterbalanced, varied-order measurements and held-out environments; do not promote from this A/B alone. |
| D002 / 2026-11-17 | Keep setup deterministic. Optional local AI may explain typed findings and propose bounded actions, but cannot certify protection or approve its own changes. | [setup engine](cli/setup.md), [physical evidence](evidence/SETUP_HARDWARE_20261117.json). Revisit the interface only with adversarial tool/approval and secret-exposure evaluations. |
| D003 / 2026-11-17 | Continue a zero-budget development path and use voluntary funding disclosure. No paid audit or new cloud spend is authorized. | Owner instruction of 17 November, [funding record](FUNDING.md). Revisit when the owner reports funding or authorizes expenditure; unpaid independent review remains possible. |
| D004 / 2026-11-17 | Publish CCC-informed principles, conduct and accountable maintainer-led governance while retaining Apache-2.0. | [principles](PRINCIPLES.md), [conduct](../CODE_OF_CONDUCT.md), [governance](GOVERNANCE.md). Independent appeal capacity, usability studies and external security review remain open. No traffic monitoring or additional license restriction is introduced. |
| D005 / 2026-11-17 | Automatically push and integrate validated, cryptographically verified signed commits under the owner's standing authorization. Preserve history and repository protections. | [project workflow](../AGENTS.md). A source publication does not authorize a live deployment, cost or hardware-secret change. |
| D006 / 2026-11-17 | Ship a pinned offline runtime; preserve live environments on failed upgrades and refuse removal beneath a guard. Refresh the inherited interpreter/TLS pin before distribution. | [Offline guide](OFFLINE_INSTALLATION.md), [four-distribution evidence](evidence/OFFLINE_PACKAGE_20261117.json). Native packages, crash-interrupted/live upgrades and current-release reboot protection remain open gates. |
