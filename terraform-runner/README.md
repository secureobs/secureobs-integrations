# SecureObs Terraform runner

Ephemeral, sandboxed container that powers **managed** (server-side) Terraform
IaC analysis. SecureObs launches one of these per analysis in Azure Container
Instances; it clones the customer repo with a short-lived GitHub App
installation token, generates a Terraform plan **without backend state or a
resource refresh**, sanitizes it with the shared allowlist, and submits only the
topology to the SecureObs API. The raw plan never leaves the container.

This is the zero-config alternative to running the `secureobs/scanner` image in
the customer's own CI: no pipeline YAML, no cloud credentials, no OIDC.

## Why a separate image

It reuses the **exact** sanitizer (`scanner-image/scripts/infrastructure/`) and
API client (`scanner-image/scripts/api_client.py`) the scanner image uses, so
the managed graph is byte-for-byte compatible with the pipeline-produced graph.
Keeping Terraform out of the customer-facing scanner image avoids bloating every
CI pull with a binary only the server-side runner needs.

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
  --terraform-root infra --terraform-version 1.9.8 \
  [--source-revision <sha>] [--terraform-root-id <id>] \
  [--var-file vars/prod.tfvars] [--var key=value]
```

Exit `0` on success, `2` on any failure. The last stdout line is a JSON status
(`{"secureobsRunnerStatus": "succeeded"|"failed", ...}`) the SecureObs run
monitor parses from the container log tail.

## Security

- Runs as an unprivileged user; the container is destroyed after each run.
- Plan uses `-refresh=false -backend=false` with **no** cloud credentials, so it
  never reads remote state or touches deployed resources.
- Terraform is downloaded on demand and verified against HashiCorp's
  GPG-signed `SHA256SUMS` before use.
- The installation token and API key are never logged or echoed.
