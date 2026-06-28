# Changelog

## Unreleased

**Feature (inline PR comments):** `pr-comment` now annotates pull requests **inline on the exact file and line** of high-signal findings (blocking + CRITICAL/HIGH), in addition to the existing upserted summary comment. The scanner fetches a slim, PR-safe finding list for the run (`GET /api/findings/by-run` — never includes code snippets or raw payloads, so a leaked secret can't be echoed into a PR), reads the PR diff, and only comments on lines the PR actually changed (findings on unchanged code are tallied in the summary). Works on both GitHub Actions (review comments via the built-in `GITHUB_TOKEN` + `pull-requests: write` — no customer setup) and Azure DevOps (PR threads with file/line `threadContext`; the build service needs *Contribute to pull requests*). Prior SecureObs inline comments are removed before re-posting so re-runs don't stack duplicates. Inline decoration is fully best-effort — any failure falls back to the summary comment and never breaks the pipeline. Capped at 50 inline comments per run.

**Feature (two IaC fidelity modes):** Terraform analysis now always runs Checkov. Static mode scans the selected Terraform root and then builds a credential-free HCL topology. Plan mode scans the Terraform plan with source enrichment and Checkov deep analysis before uploading the sanitized plan topology. Generated GitHub workflows use customer-owned OIDC and generated Azure DevOps pipelines use customer-owned service connections; SecureObs never receives cloud credentials. Generated IaC workflows use `--iac-only` so they do not repeat unrelated whole-repository SAST/SCA scans for every Terraform root. Checkov raw payloads are reduced to safe rule/resource/location metadata and never include source code blocks or evaluated values.

**Feature (topology containment fields):** the infrastructure allowlist now preserves `resource_group_name` across resource types, plus `azurerm_resource_group` and relationship fields (`network_security_group_name`), so the server can reconstruct the real resource-group ▸ VNet ▸ subnet ▸ resource hierarchy and link private endpoints to their target service. Still allowlist-first — only these named, non-sensitive identifiers are added.

**Fix (static topology correctness):** unresolved expressions are marked unknown instead of being interpreted as configured values, `count = 0` / empty `for_each` resources are omitted, references inside local modules retain their module address, repeated local-module instances are preserved, and `.tfvars.json` auto-loading is supported.

**Hardening (IaC onboarding and execution):** plan workflows now keep the committed dependency lock file strictly read-only, map customer-owned `TF_VAR_*` secrets by variable name only, and use the AzureRM provider's Azure DevOps workload-identity service-connection identifier. Managed static runs reject unpinned runner images, unsafe refs/paths, repository escapes, oversized parse workloads, and Checkov executions over 15 minutes. Checkov fingerprints now include the Terraform resource address so findings for expanded instances are not collapsed.

**Fix (large finding sets):** scanner finding ingestion is split by both item count and serialized request size, preventing large Checkov result sets from exceeding the API's 5,000-row / 8 MiB request limits.

## v1.3.0 — 2026-06-24

**Feature (credential-free IaC analysis):** `scan` now accepts `--terraform-root <relative-dir>` for **static** infrastructure analysis. The scanner parses the Terraform HCL directly with `python-hcl2` — no `terraform plan`, no `terraform init`, and **no cloud credentials** — resolving variable defaults / `.tfvars` and following local modules, then uploads only the allowlisted topology. This removes the Azure/AWS/GCP credential requirement that `terraform plan` imposes (the `azurerm` provider acquires a real token even for a refresh-free plan). `--terraform-var-file <relative-path>` (repeatable) supplies `.tfvars` for variable resolution. The higher-fidelity `--terraform-plan-json` path remains for users who already produce a plan in their own pipeline.

## v1.2.12 — 2026-06-19

**Feature (IaC attack-path analysis):** `scan` now accepts four new flags for infrastructure analysis. Pass `--terraform-plan-json <relative-path>` to supply a pre-generated Terraform plan JSON; the scanner sanitizes it locally and uploads only the allowlisted resource topology — the raw plan is never transmitted. `--source-revision <sha>` records the VCS commit the plan was generated from. `--terraform-root-id <id>` distinguishes multiple Terraform roots in a monorepo. `--require-infrastructure-analysis` causes a non-zero exit when the plan is absent or the upload fails. Ordinary scanner failures are not affected by this flag.

## v1.2.10 — 2026-06-17

**Fix (base image):** Revert the scanner base image from `python:3.14-slim` back to the supported `python:3.12-slim`. The bundled, version-pinned security tools are validated against 3.12; the automatic bump to bleeding-edge 3.14 was unvetted. Dependabot is now pinned to Python 3.12.x for this image so the jump cannot recur without a manual review.

**Fix (auth robustness):** `SECUREOBS_API_KEY` is now whitespace-stripped before use. A key that picked up a trailing newline or space from a CI secret store was sent verbatim in the `X-Api-Key` header and rejected as a `401 Authentication failed` (a newline was rejected even earlier by urllib3's header validation). A correct key with stray surrounding whitespace now authenticates.

## v1.2.7 — 2026-05-10

**Feature (CI automation):** Changelog is now auto-generated from this file on every scanner build — `scripts/generate-changelog.js` parses CHANGELOG.md and writes `changelog.data.ts`. EF Core migrations run automatically in CI via a migration bundle built and uploaded as an artifact before the API deploys.

## v1.2.6 — 2026-05-10

**Feature (version tracking):** Pipeline now reports its running image version on every ingest. The dashboard shows a real "update available" warning only when a project has actually scanned — no false positives from unconfigured pipelines.

## v1.2.5 — 2026-05-09

**Feature (scan summary):** After all scanners complete, `secureobs-scanner scan` now prints a formatted per-scanner summary table showing findings ingested, new-after-dedup count, and skip/error reasons. Unknown scanner keys (catalog ahead of image) and driver exceptions also appear in the table. The total line gives an at-a-glance count across all scanners. No change to exit codes or API behaviour.

## v1.2.4 — 2026-05-09

**Fix (ESLint):** Upgrade to `eslint-plugin-security@^3.0.1`. v3 ships a proper flat-config `recommended` export that does not create a circular `plugins` reference under ESLint 8. Also removed the redundant `"plugins": ["security"]` key from `eslint-secureobs.json` — extending `plugin:security/recommended` already registers the plugin.

**Fix (OSV-Scanner):** Switch from capturing stdout to writing JSON to `/tmp/osv-results.json` via `--output`. OSV-Scanner interleaves progress messages and lockfile warnings on stdout, corrupting the JSON stream. Reading from the output file is reliable. Exit codes 0 (clean) and 1 (vulns found) are treated as success; any other code is a real failure. Per-file parse warnings (e.g. complex `pom.xml`) are now logged at WARNING and do not abort the run — findings from other lockfiles in the same repo are captured.

**Fix (logging):** Skips caused by a non-zero tool exit are now logged at ERROR in the orchestrator, including the exit code and the last 500 characters of stderr. Non-exit skips (no JS files, no lockfiles) remain at INFO. `ScanResult` gains two optional diagnostic fields (`exit_code`, `stderr_tail`) to carry this information — the fundamental result model is unchanged.

**Fix (pipeline YAML):** Azure DevOps job and step display names updated to accurately reflect the full scanner suite.

## v1.2.3 — 2026-05-09

**Bug fix (OSV-Scanner):** Rewrote scanner driver to prioritise JSON output over exit code. OSV-Scanner exits non-zero when individual lockfiles fail to parse (e.g. complex Maven `pom.xml` with unresolvable parent POMs) but may still emit valid JSON for files it *could* scan — those partial results are now captured instead of discarded. When no JSON is produced at all the driver returns zero findings instead of crashing the pipeline. Also reordered candidates to try v2.x syntax first.

**Bug fix (ESLint, continued from v1.2.1):** Previous releases fixed the Dockerfile but the image was not rebuilt. This release triggers a fresh image build that includes `eslint-plugin-security@1.7.1`.

## v1.2.2 — 2026-05-09

**Bug fix:** OSV-Scanner driver no longer crashes the pipeline on exit code `2` (partial scan — some lockfiles unresolvable) or when no JSON is produced. Both failure paths now return a graceful skip instead of calling `sys.exit(2)`. Removed unused `sys` import.

## v1.2.1 — 2026-05-09

**Bug fix:** Pin `eslint-plugin-security` to `1.7.1` (was `2.1.1`). v2.x of the plugin uses ESLint 9 flat-config format, which causes a circular-reference `JSON.stringify` crash (exit 2) when loaded by ESLint 8. The scanner was silently skipping ESLint on all runs as a result.

## v1.2.0 — 2026-05-02

Bundled multi-scanner runtime + universal ingest API.

**Requires SecureObs API with `POST /api/findings/bulk-universal` deployed first.**

- Dockerfile now installs **Trivy**, **Bandit**, **Checkov**, **OSV-Scanner**, **Node.js/npm**, plus global **eslint@8 + eslint-plugin-security**.
- Drivers for **`trivy`**, **`bandit`**, **`checkov`**, **`osv-scanner`**, and **`eslint-security`** POST rows to **`/api/findings/bulk-universal`** (`UniversalFindingDto` shape).
- **`codeql`**, **`sonarqube`**, **`snyk`**, **`owasp-zap`** remain **intentionally skipped** inside this image — they expect vendor CI, tokens, SARIF, or hosted DAST rather than a generic tarball scan. Logs are **`INFO`** (not alarming): "not bundled … use vendor integration".
- **Semgrep** / **GitLeaks** unchanged — still hit their typed bulk endpoints (`/api/findings/bulk-semgrep`, `/api/findings/bulk-gitleaks`).

## v1.1.0 — 2026-05-02

Dynamic scanner selection.

- The `scan` subcommand now calls `GET /api/projects/{projectId}/scanners/active` at the start of every run and executes only the scanners the user has enabled in the SecureObs dashboard. Pipeline YAML stays identical for every project — adding or removing a scanner from the dashboard takes effect on the next CI run with **zero pipeline edits**.
- Driver registry maps catalog keys to runners. (As of **v1.2.0** most catalog keys execute real scanners; **`codeql` / `sonarqube` / `snyk` / `owasp-zap`** still log an informational skip — see below.)
- Defensive fallback: if the active-scanners endpoint is unreachable (network / 5xx), the orchestrator falls back to the default set (`semgrep`, `gitleaks`) so a degraded control plane never breaks a user's pipeline. Auth failures and unknown projects still abort hard with exit code 1.
- Scanner runner signature extended with an optional `config` argument (per-project tuning surfaced from `ProjectScanner.Config`).
- Catalog-vs-image skew: unknown keys from the API are skipped with a warning; older APIs without `bulk-universal` require upgrading the backend before **`trivy` / `bandit` / …** findings persist.

## v1.0.0 — 2026-04-27

Initial release.

- Bundled Docker image with Semgrep (p/ci ruleset) and GitLeaks v8.21.2
- `scan` subcommand: runs both scanners against `/workspace`, posts findings to SecureObs API
- `gate` subcommand: queries API for blocking findings, exits 3 if blocked
- `pr-comment` subcommand: posts or updates a single PR comment with scan status (Azure DevOps and GitHub Actions)
- Marker-based comment deduplication — one comment per PR, updated on each run
- Structured logging to stderr; `SECUREOBS_DEBUG=1` enables verbose output
- Retry logic on transient API errors (3 attempts, exponential backoff)
