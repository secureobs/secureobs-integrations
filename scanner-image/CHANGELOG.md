# Changelog

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
