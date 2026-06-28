# SecureObs Canary (GitHub Actions)

This repo (`secureobs/webgoat`, a copy of OWASP WebGoat — a deliberately
vulnerable app) is a **SecureObs internal canary**. It does not exist to ship
WebGoat; it exists to continuously prove that the SecureObs scanner image and
the public CI templates still work the way customers consume them.

Two workflows run on every push and PR (and can be dispatched on demand):

| Workflow | Path tested | Catches |
|---|---|---|
| `.github/workflows/secureobs-canary.yml` | Direct `docker run secureobs/scanner:v1` (`scan` → `gate` → `pr-comment`) | Image regressions, broken CLI flags, broken gate exit codes, ingestion failures. |
| `.github/workflows/secureobs-canary-reusable.yml` | `uses: secureobs/secureobs-integrations/.github/workflows/secureobs.yml@v1` | Broken `uses:` ref, unpublished/var mirror `v1` tag, breaking changes to the reusable workflow interface. |

Expected outcome on a healthy system: the scan ingests findings (WebGoat is full
of HIGH/CRITICAL issues) and the **gate step fails the run with exit code 3**.
That red gate is the *success* condition for the canary's blocking-path
assertion — the SecureObs self-test in the `secure-obs` repo verifies it via the
API. (To prove the clean/pass path, point a second canary project at a clean
revision or disable blocking in that project's Build-gate settings.)

## Required configuration (you set these)

In `Settings → Secrets and variables → Actions`:

| Name | Kind | Value | Status |
|---|---|---|---|
| `SECUREOBS_API_KEY` | **secret** | Project-scoped ingestion key for the canary project | **TODO — set this** |
| `SECUREOBS_PROJECT_ID` | variable | Canary project GUID (project → Integration panel) | **TODO — set this** |
| `SECUREOBS_TENANT_ID` | variable | Canary tenant GUID (Settings → Organization) | **TODO — set this** |
| `SECUREOBS_API_URL` | variable (optional) | Only to point the canary at a non-prod SecureObs; must keep the `/api` suffix | optional |

`GITHUB_TOKEN` is automatic (used by the `pr-comment` step to post one PR
comment). No API keys or IDs are ever hardcoded in the workflow YAML.

## How the self-test triggers these

The meta-verification workflow in `secure-obs`
(`.github/workflows/template-canary-selftest.yml`) dispatches
`secureobs-canary.yml` and `secureobs-canary-reusable.yml` via the GitHub REST
API with unique `pipeline-run-id` inputs, then polls the SecureObs API for those
run ids to confirm findings were ingested and the gate reports blocking. See
`secure-obs/docs/TEMPLATE_CANARY_SELFTEST.md`.

## Interpreting failures

| Symptom | Likely cause |
|---|---|
| `Canary not configured … SECUREOBS_*` | One of the three secrets above is unset. |
| `401`/`403` from ingestion | API key revoked, expired, or scoped to a different project than `SECUREOBS_PROJECT_ID`. |
| Reusable canary fails at `uses:` resolution | The `secureobs/secureobs-integrations` mirror or its `v1` tag is missing — re-run `sync-integrations.yml` / cut an `integrations-v*` release. |
| Scan succeeds, gate passes (exit 0) when you expected red | Findings didn't ingest, or the project's Build-gate policy is "Never block". |
| `docker: command not found` | Runner without Docker; use `ubuntu-latest`. |
