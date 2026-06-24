# SecureObs managed Terraform plan runner.
#
# Build context MUST be the `integrations/` directory so this image can copy the
# SAME sanitizer + API client used by the scanner image — a single source of
# truth keeps the server-side managed analysis byte-for-byte compatible with the
# graph the customer pipelines already produce.
#
#   docker build -f terraform-runner/Dockerfile -t secureobs/terraform-runner .
#
# Terraform itself is NOT baked in: runner.py downloads the user's pinned
# version on demand and verifies it against HashiCorp's GPG-signed SHA256SUMS.
# This keeps the image small and supports every customer's pinned version.
FROM python:3.12-slim
LABEL maintainer="Jason Achkar Diab"

ARG IMAGE_VERSION=dev
ENV SECUREOBS_IMAGE_VERSION=${IMAGE_VERSION}

# Shared keyring location for HashiCorp's signing key, readable by the runner
# user at runtime so `gpg --verify` of the Terraform SHA256SUMS works.
ENV GNUPGHOME=/opt/secureobs-keyring

# requests + its TLS/HTTP chain, pinned to the exact versions the scanner image
# uses so the authenticated submit path is reproducible across both images.
ARG REQUESTS_VERSION=2.32.3
ARG URLLIB3_VERSION=2.7.0
ARG CERTIFI_VERSION=2026.5.20
ARG IDNA_VERSION=3.18
ARG CHARSET_NORMALIZER_VERSION=3.4.7

# HashiCorp code-signing key fingerprint (also pinned in runner.py). Fetched from
# the well-known URL at build time and the imported fingerprint is asserted, so
# no key bytes are hardcoded but an unexpected key fails the build.
ARG HASHICORP_FPR=C874011F0AB405110D02105534365D9472D7468F

# git + gnupg are needed at runtime (clone + SHA256SUMS signature check);
# curl + ca-certificates support the build-time key fetch and runtime TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
    && pip install --no-cache-dir --only-binary=:all: \
        "certifi==${CERTIFI_VERSION}" \
        "charset-normalizer==${CHARSET_NORMALIZER_VERSION}" \
        "idna==${IDNA_VERSION}" \
        "requests==${REQUESTS_VERSION}" \
        "urllib3==${URLLIB3_VERSION}" \
    # Unprivileged user — untrusted Terraform must never run as root.
    && useradd --create-home --uid 10001 runner \
    # Import HashiCorp's signing key into a shared keyring and assert its
    # fingerprint, then hand the keyring to the runner user.
    && mkdir -p "${GNUPGHOME}" \
    && chmod 700 "${GNUPGHOME}" \
    && curl -fsSL https://www.hashicorp.com/.well-known/pgp-key.txt -o /tmp/hashicorp.asc \
    && gpg --homedir "${GNUPGHOME}" --import /tmp/hashicorp.asc \
    && gpg --homedir "${GNUPGHOME}" --fingerprint "${HASHICORP_FPR}" >/dev/null \
    && rm -f /tmp/hashicorp.asc \
    && chown -R runner:runner "${GNUPGHOME}" \
    && chmod -R 700 "${GNUPGHOME}" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Single source of truth: the sanitizer + API client come straight from the
# scanner image source. (Context is `integrations/`.)
COPY scanner-image/scripts/infrastructure/ /runner/infrastructure/
COPY scanner-image/scripts/api_client.py   /runner/api_client.py
COPY terraform-runner/runner.py            /runner/runner.py

RUN chown -R runner:runner /runner
USER runner

WORKDIR /runner
ENTRYPOINT ["python3", "/runner/runner.py"]
