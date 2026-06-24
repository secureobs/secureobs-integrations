# SecureObs Terraform runner

Ephemeral, sandboxed container that powers **managed** (server-side) Terraform
IaC analysis. SecureObs launches one of these per analysis in Azure Container
Instances; it clones the customer repo with a short-lived GitHub App
installation token, analyses the Terraform **statically** (`python-hcl2`, no
`terraform plan`, no cloud credentials), runs Checkov, sanitizes the topology
with the shared allowlist, and submits Checkov findings plus sanitized topology
to the SecureObs API.

This is the zero-config alternative to running the `secureobs/scanner` image in
the customer's own CI: no pipeline YAML, no cloud credentials, no OIDC.

## Why a separate image

It reuses the same static extractor, sanitizer, Checkov driver, and API client
as the scanner image. The ingestion schema is shared with plan-based analysis,
while the graph records that static source analysis has lower fidelity than a
resolved plan. The image contains no Terraform binary.

> The Docker build context is `integrations/` (not this directory) so the
> sanitizer can be copied from the scanner image source.

```bash
cd integrations
docker build -f terraform-runner/Dockerfile -t secureobs/terraform-runner .
```

## Contract

Secrets are passed by **environment**, never on the command line:

| Env var | Purpose |
| --- | --- |
| `SECUREOBS_API_URL` | Base API URL, e.g. `https://api.secureobs.com/api` |
| `SECUREOBS_API_KEY` | Short-lived, project-scoped ingestion key |
| `GITHUB_INSTALLATION_TOKEN` | Short-lived GitHub App installation token |

Non-secret parameters are CLI flags:

```
runner.py \
  --project-id <guid> --tenant-id <guid> --run-id <guid> \
  --repo-url https://github.com/owner/repo.git --ref main \
  --terraform-root infra \
  [--source-revision <sha>] [--terraform-root-id <id>] \
  [--var-file vars/prod.tfvars]
```

Exit `0` on success, `2` on any failure. The last stdout line is a JSON status
(`{"secureobsRunnerStatus": "succeeded"|"failed", ...}`) the SecureObs run
monitor parses from the container log tail.

## Security

- Runs as an unprivileged user; the container is destroyed after each run.
- **No `terraform plan`, no cloud credentials, no remote state** — the HCL is
  parsed statically, so the analysis can never read or touch deployed resources.
- Checkov findings and only the allowlisted topology are uploaded; the
  installation token and API key are never logged or echoed.
- Git authentication is passed through one-shot Git environment configuration,
  not the clone URL or process arguments.
- Local modules and Terraform symlinks are constrained to the cloned repository;
  parsing also has file-size, file-count, resource-count, edge-count, and timeout limits.
