# SecureObs Template Canaries

Single source of truth for the end-to-end canary pipelines that prove the
SecureObs scanner image and CI templates work the way customers consume them.
These files are the **canonical copies**; they are mirrored into the two
SecureObs-owned WebGoat test repos and exercised continuously.

```
integrations/canary/
├── github/                       # → GitHub repo  secureobs/webgoat
│   ├── secureobs-canary.yml          # .github/workflows/  (direct docker run)
│   ├── secureobs-canary-reusable.yml # .github/workflows/  (uses: public reusable wf)
│   └── SECUREOBS_CANARY.md           # docs/
└── azuredevops/                  # → Azure DevOps repo  jasonachkardiab/WebGoat
    ├── azure-pipelines.yml           # repo root (self-contained, no service conn)
    ├── azure-pipelines-extends.yml   # repo root (extends: public template)
    └── SECUREOBS_CANARY_SETUP.md     # how to import into ADO (step by step)
```

## What each canary proves

| Canary | Proves |
|---|---|
| GitHub direct image | `secureobs/scanner:v1` runs, CLI flags/exit codes intact, findings ingest, gate exits 3 on blocking. |
| GitHub reusable workflow | `uses: secureobs/secureobs-integrations/.github/workflows/secureobs.yml@v1` still resolves and the reusable interface (inputs + `api-key` secret) is unbroken. |
| ADO self-contained | Same as GitHub direct image, on Azure Pipelines, with no service connection. |
| ADO extends template | The `extends:` template + `SecureObs-GitHub` service connection path still compiles and runs. |

## Driven by the meta-verification self-test

The GitHub Actions workflow `.github/workflows/template-canary-selftest.yml`
(in this repo) triggers all four canaries after the public mirror sync completes
successfully (nightly or manual dispatch works too), then polls the SecureObs
API to assert each platform recorded a run, findings were ingested (≥1
CRITICAL), and the gate job/step is the failing unit. Pull requests build/vet
the Go runner but do not run external canaries because those exercise published
artifacts. See
[`docs/TEMPLATE_CANARY_SELFTEST.md`](../../docs/TEMPLATE_CANARY_SELFTEST.md) and
the architecture note [`docs/TEMPLATE_CANARY_ARCHITECTURE.md`](../../docs/TEMPLATE_CANARY_ARCHITECTURE.md).

## Keeping copies in sync

When you change a canary here, mirror it into the corresponding WebGoat repo
(GitHub paths shown above; ADO via `azuredevops/SECUREOBS_CANARY_SETUP.md`). The
self-test runs the copies that live in the WebGoat repos, so drift between this
folder and those repos is itself a thing to watch.
