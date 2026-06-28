# SecureObs Canary — Azure DevOps setup

This folder holds the two Azure DevOps canary pipelines for the ADO `WebGoat`
repo (`https://dev.azure.com/jasonachkardiab/WebGoat`). Because this environment
cannot push to Azure DevOps, follow these exact steps to install them. Total
time once you have the SecureObs IDs: ~10 minutes.

| File | Becomes (in the ADO WebGoat repo) | Path tested |
|---|---|---|
| `azure-pipelines.yml` | `azure-pipelines.yml` (repo root) | Self-contained `docker run` — **no service connection** |
| `azure-pipelines-extends.yml` | `azure-pipelines-extends.yml` (repo root) | `extends:` the public template — **needs `SecureObs-GitHub` service connection** |

> Start with the self-contained pipeline. Only add the `extends` one once the
> first is green — it has the extra service-connection dependency.

---

## 1. Add the files to the ADO repo

Clone the ADO repo and copy both YAML files into its root, then push:

```bash
git clone https://jasonachkardiab@dev.azure.com/jasonachkardiab/WebGoat/_git/WebGoat
cd WebGoat
# copy azure-pipelines.yml and azure-pipelines-extends.yml from
# secure-obs/integrations/canary/azuredevops/ into this repo root
git checkout -b feature/secureobs-canary
git add azure-pipelines.yml azure-pipelines-extends.yml
git commit -m "ci: add SecureObs canary pipelines (self-contained + extends)"
git push -u origin feature/secureobs-canary
```

Open a PR in ADO (Repos → Pull requests) or push straight to a branch you'll
build from.

## 2. Create the `secureobs` variable group

`Project settings → Pipelines → Library → + Variable group`:

| Variable | Secret? | Value |
|---|---|---|
| `SECUREOBS_API_KEY` | **Yes (lock)** | Project-scoped ingestion key for the canary project |
| `SECUREOBS_PROJECT_ID` | No | Canary project GUID — **TODO: fill in** |
| `SECUREOBS_TENANT_ID` | No | Canary tenant GUID — **TODO: fill in** |
| `SECUREOBS_API_URL` | No (optional) | Only to target a non-prod SecureObs; must keep the `/api` suffix |

Name the group exactly `secureobs`. Save.

## 3. Create the self-contained pipeline

1. `Pipelines → New pipeline → Azure Repos Git → WebGoat`.
2. `Existing Azure Pipelines YAML file` → select `/azure-pipelines.yml` on your branch.
3. On the pipeline → `Edit` → `…` → `Triggers` (or the YAML's `variables:`) →
   link the **`secureobs`** variable group (Library → this pipeline). Save.
4. Run it. Expected: scan ingests WebGoat findings; the **Gate job fails with
   exit 3** (blocking findings exist). That red gate is the success signal for
   the canary's blocking path.

## 4. (Optional) Create the `extends` pipeline

Only needed to canary the template path.

1. **GitHub service connection**: `Project settings → Service connections →
   New service connection → GitHub`. Authorize an account/PAT that can read
   `secureobs/secureobs-integrations`. Name it **exactly** `SecureObs-GitHub`.
   On the connection, allow it to be used by the pipeline (or check
   "Grant access permission to all pipelines").
2. Edit `azure-pipelines-extends.yml` and replace `TODO-CANARY-PROJECT-GUID` /
   `TODO-CANARY-TENANT-GUID` with the real GUIDs (these are template parameters,
   not variables).
3. `New pipeline → Existing YAML` → select `/azure-pipelines-extends.yml`.
4. Link the `secureobs` variable group (the template reads `$(SECUREOBS_API_KEY)`).
5. Ensure the mirror tag `v1` exists on `secureobs/secureobs-integrations`
   (the `sync-integrations.yml` job in secure-obs produces it).
6. Run it.

> If you see `Repository … uses endpoint SecureObs-GitHub which could not be
> found or is not authorized`, the service connection is missing, misnamed, or
> not authorized for this pipeline.

## 5. Enable PR comments (optional)

For the `PrComment` job to post:
- Pipeline → `…` → `Settings` → enable **"Allow scripts to access the OAuth token"**.
- Give the build service identity (`<Project> Build Service`) **Contribute to
  pull requests** on the WebGoat repo (`Project settings → Repositories →
  WebGoat → Security`).

## 6. Wire the pipelines into the self-test (so secure-obs can queue them)

The meta-verification workflow queues these via the Azure DevOps REST API. After
creating each pipeline, note its **definition ID** (in the pipeline URL:
`…/_build?definitionId=NN`). You will set these as GitHub secrets/vars on the
`secure-obs` repo for `template-canary-selftest.yml`:

| GitHub secret/var (on secure-obs) | Value |
|---|---|
| `AZDO_ORG_URL` (var) | `https://dev.azure.com/jasonachkardiab` |
| `AZDO_PROJECT` (var) | `WebGoat` |
| `AZDO_PIPELINE_ID` (var) | definition ID of the self-contained pipeline |
| `AZDO_PAT` (secret) | Azure DevOps PAT with **Build: Read & execute** scope |

The runner passes a unique `pipelineRunId` template parameter when it queues both
pipelines so it can poll SecureObs for the exact run it triggered.

---

## Required configuration summary

| Item | Where | Secret? |
|---|---|---|
| `SECUREOBS_API_KEY` | ADO variable group `secureobs` | Yes |
| `SECUREOBS_PROJECT_ID` / `SECUREOBS_TENANT_ID` | ADO variable group `secureobs` (self-contained) **and** template params (extends) | No |
| `SecureObs-GitHub` | ADO GitHub service connection (extends only) | n/a |
| `AZDO_PAT` | GitHub secret on secure-obs (for the self-test) | Yes |
