# SecureObs Integrations

Everything that runs in the **customer's** CI/CD pipeline — as opposed to the rest of the repository, which is the SecureObs service itself. This folder exists so that the user-facing integration surface is one cohesive, versioned unit: it is mirrored on every `integrations-v*` tag to the public [`secureobs/secureobs-integrations`](https://github.com/secureobs/secureobs-integrations) repo (the main repo is private, but `extends:` / `uses:` template references require a public source — see ADR-006 in the root README).

---

## What's in this folder

| Path | Description |
|---|---|
| [scanner-image/](scanner-image/) | The `secureobs/scanner` Docker image: Semgrep, GitLeaks, Trivy, Bandit, Checkov, OSV-Scanner, and ESLint (security plugin), plus the Python orchestrator exposing the `scan` / `gate` / `pr-comment` subcommands. This is the only artifact users actually execute. |
| [pipeline-templates/azuredevops/](pipeline-templates/azuredevops/) | Azure DevOps `extends:` template wrapping the image's three subcommands in three jobs. **Requires a GitHub service connection** (`SecureObs-GitHub`) in the user's ADO project to fetch the template — which is why the dashboard now generates a self-contained `azure-pipelines.yml` by default and this template is the optional path. |
| [pipeline-templates/github/](pipeline-templates/github/) | Source GitHub Actions reusable workflow (`workflow_call`) with `project-id` / `tenant-id` / `image-tag` / `fail-on-blocking` inputs and the `api-key` secret. The mirror sync publishes this file to `.github/workflows/secureobs.yml`, which is the only path GitHub allows callers to reference with `uses:`. |
| [canary/](canary/) | **Internal end-to-end canaries.** Canonical GitHub + Azure DevOps pipelines run against OWASP WebGoat that continuously prove the image + templates work the way customers consume them. Driven by `.github/workflows/template-canary-selftest.yml` (see below). |

---

## Quick reference

**Docker image:** `secureobs/scanner:v1` — [Docker Hub](https://hub.docker.com/r/secureobs/scanner) · [README](scanner-image/README.md)

**Azure DevOps (recommended):** paste the self-contained YAML generated on your project page — runs the image directly, needs only the `SECUREOBS_API_KEY` secret variable, no service connections. See [docs/quickstart-azure-devops.md](../docs/quickstart-azure-devops.md).

**Azure DevOps (template variant):** extend from `pipeline-templates/azuredevops/secureobs.yml` via the `secureobs/secureobs-integrations` public mirror — requires a GitHub service connection named `SecureObs-GitHub` authorized for the pipeline. Declared parameters: `projectId`, `tenantId`, `imageTag`, `failOnBlocking` (passing anything else is a compile-time error in ADO).

**GitHub Actions:** call `secureobs/secureobs-integrations/.github/workflows/secureobs.yml@v1` (or pin a specific `vX.Y.Z` tag). Declared inputs: `project-id`, `tenant-id`, `image-tag`, `fail-on-blocking`; secret: `api-key`.

---

## Continuous verification (canaries)

Because a change to `scanner-image/**` or `pipeline-templates/**` can break the
real customer integration while every unit test stays green, an end-to-end
**canary** runs the published templates against [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
(a deliberately vulnerable app) on **both** GitHub Actions and Azure DevOps:

- Canonical pipelines live in [`canary/`](canary/) and are mirrored into the
  SecureObs-owned WebGoat test repos (`secureobs/webgoat` on GitHub, the
  `WebGoat` repo on Azure DevOps).
- The meta-verification workflow `.github/workflows/template-canary-selftest.yml`
  triggers them after the public mirror sync completes (or on demand), then
  polls the SecureObs API to confirm each platform recorded a run, ingested
  findings (≥1 CRITICAL), and that the build gate blocked correctly. Runner:
  [`tools/TemplateCanaryRunner/`](../tools/TemplateCanaryRunner/) (Go).
- Playwright UI tests (`SecureObs.Dashboard/tests/playwright`) assert the
  dashboard reflects those runs and findings.

See [`docs/TEMPLATE_CANARY_ARCHITECTURE.md`](../docs/TEMPLATE_CANARY_ARCHITECTURE.md),
[`docs/TEMPLATE_CANARY_SELFTEST.md`](../docs/TEMPLATE_CANARY_SELFTEST.md), and
[`SecureObs.Dashboard/PLAYWRIGHT_TESTS.md`](../SecureObs.Dashboard/PLAYWRIGHT_TESTS.md).

## Versioning policy

This folder follows [semver](https://semver.org). Version tags on the `secureobs/secureobs-integrations` public mirror control what pipeline templates users pin to.

| Change type | Version bump |
|---|---|
| Breaking change to template interface or Docker image behaviour | Major (`v2`) |
| New subcommand, new parameter, new scanner | Minor (`v1.1`) |
| Bug fix, dependency update, docs | Patch (`v1.0.1`) |

Exact version tags (`v1.2.3`) are immutable once published. Floating minor and major tags (`v1.2`, `v1`) are moved by the sync workflow to the latest stable release in that line, so users pinned to `v1` receive non-breaking updates automatically.

---

## Migration from script-based integration

If you set up SecureObs before April 2026 you may be using the script-based integration. Both approaches post to the same API endpoints and produce the same results.

**Old pipeline (still works — no action needed):**
```yaml
# Installs Python, downloads scripts from CDN, runs them directly
- script: pip install semgrep requests
- script: python3 secureobs/semgrep_scan.py ...
```

**New pipeline (recommended for new projects):**
```yaml
extends:
  template: pipeline-templates/azuredevops/secureobs.yml@secureobs
  parameters:
    projectId: 'your-project-id'
    tenantId: 'your-tenant-id'
```

The old scripts are still hosted and functional. They're marked deprecated in the repo but will not be removed without a major version notice.

**What you gain by migrating:**
- Single YAML line instead of 50+ lines
- Scanner versions pinned and tested together in the Docker image
- Marker-based PR comment deduplication (one comment per PR, updated in place)
- Structured logging and proper exit codes

---

## For SecureObs maintainers

### Public mirror setup (one-time)

1. Create a public GitHub repo: `secureobs/secureobs-integrations`
2. Generate a deploy key (SSH keypair):
   ```bash
   ssh-keygen -t ed25519 -C "integrations-sync" -f integrations_deploy_key
   ```
3. Add the **public key** as a deploy key on `secureobs-integrations` (write access).
4. Add the **private key** as a secret named `INTEGRATIONS_DEPLOY_KEY` on this (private) repo.

### Publishing a release

1. Bump the version in `scanner-image/VERSION`
2. Commit and push to `main` — the sync action auto-mirrors changes to the public repo
3. Tag with `integrations-v{VERSION}` (e.g. `integrations-v1.1.0`):
   ```bash
   git tag integrations-v1.1.0
   git push origin integrations-v1.1.0
   ```
   The sync action mirrors this as `v1.1.0` on the public repo and updates the floating `v1.1` and `v1` tags. The scanner image CI performs this step automatically after it builds the Docker image; `sync-integrations.yml` also has a `workflow_run` backstop because the scanner release commit uses `[skip ci]`.
4. Run `integrations/scanner-image/build-and-push.sh` to publish the Docker image to Docker Hub.
5. If the public mirror ever misses a tag, manually run **Sync integrations to public mirror** with `release_tag` set to the missing public tag (for example, `v1.2.14`).
