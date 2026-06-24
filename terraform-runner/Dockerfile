# SecureObs managed Terraform analysis runner.
#
# Build context MUST be the `integrations/` directory so this image can copy the
# SAME sanitizer + API client used by the scanner image — a single source of
# truth keeps static and plan analysis on the same ingestion schema.
#
#   docker build -f terraform-runner/Dockerfile -t secureobs/terraform-runner .
#
# CREDENTIAL-FREE: the runner clones the repo and analyses the Terraform HCL
# statically (python-hcl2) — no terraform binary, no terraform plan, no cloud
# credentials. Only the allowlisted topology is uploaded.
FROM python:3.12-slim
LABEL maintainer="Jason Achkar Diab"

ARG IMAGE_VERSION=dev
ENV SECUREOBS_IMAGE_VERSION=${IMAGE_VERSION}

# requests + its TLS/HTTP chain, pinned to the exact versions the scanner image
# uses so the authenticated submit path is reproducible across both images.
ARG REQUESTS_VERSION=2.32.3
ARG URLLIB3_VERSION=2.7.0
ARG CERTIFI_VERSION=2026.5.20
ARG IDNA_VERSION=3.18
ARG CHARSET_NORMALIZER_VERSION=3.4.7
# Pure-Python HCL2 parser (same version as the scanner image) for static analysis.
ARG PYTHON_HCL2_VERSION=4.3.5
ARG CHECKOV_VERSION=3.2.343

# git is needed at runtime to clone the repo; ca-certificates for TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && pip install --no-cache-dir --only-binary=:all: \
        "certifi==${CERTIFI_VERSION}" \
        "charset-normalizer==${CHARSET_NORMALIZER_VERSION}" \
        "checkov==${CHECKOV_VERSION}" \
        "idna==${IDNA_VERSION}" \
        "python-hcl2==${PYTHON_HCL2_VERSION}" \
        "requests==${REQUESTS_VERSION}" \
        "urllib3==${URLLIB3_VERSION}" \
    # Unprivileged user — untrusted customer HCL must never be parsed as root.
    && useradd --create-home --uid 10001 runner \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Single source of truth: the sanitizer + API client come straight from the
# scanner image source. (Context is `integrations/`.)
COPY scanner-image/scripts/infrastructure/ /runner/infrastructure/
COPY scanner-image/scripts/scanners/       /runner/scanners/
COPY scanner-image/scripts/api_client.py   /runner/api_client.py
COPY terraform-runner/runner.py            /runner/runner.py

RUN chown -R runner:runner /runner
USER runner

WORKDIR /runner
ENTRYPOINT ["python3", "/runner/runner.py"]
