FROM python:3.14-slim
LABEL maintainer="Jason Achkar Diab"

ARG IMAGE_VERSION=dev
ENV SECUREOBS_IMAGE_VERSION=${IMAGE_VERSION}

ARG TRIVY_VERSION=0.70.0
ARG OSV_SCANNER_VERSION=v1.9.2
ARG GITLEAKS_VERSION=8.21.2

# Pinned Python tool versions. Bumping any of these REQUIRES updating the
# matching SHA below if we move to hash-pinned installs.
ARG SEMGREP_VERSION=1.92.0
ARG REQUESTS_VERSION=2.32.3
ARG BANDIT_VERSION=1.7.10
ARG CHECKOV_VERSION=3.2.343

# Pinned npm package versions. --ignore-scripts is set below so lifecycle
# scripts (preinstall/postinstall) cannot execute arbitrary code from the
# transitive dependency tree at image build time.
ARG ESLINT_VERSION=8.57.0
ARG ESLINT_PLUGIN_SECURITY_VERSION=3.0.1

# SHA-256 of each downloaded release artifact, pinned for the versions above.
# Bumping a version REQUIRES updating its hash here — a mismatch fails the build,
# which is the point: a tampered or corrupted download can never be installed.
# Hashes come from each project's published release checksums file.
ARG GITLEAKS_SHA256=5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba
ARG OSV_SCANNER_SHA256=d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b
ARG TRIVY_SHA256=8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9

# Package list sorted alphabetically per Sonar dockerfile convention.
# --only-binary=:all: forces pip to use prebuilt wheels and refuses to run
# setup.py from source distributions, which removes the "pip install runs
# arbitrary Python from PyPI" supply-chain risk.
# npm --ignore-scripts prevents lifecycle scripts during install.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        nodejs \
        npm \
        wget \
    && pip install --no-cache-dir --only-binary=:all: \
        "bandit==${BANDIT_VERSION}" \
        "checkov==${CHECKOV_VERSION}" \
        "requests==${REQUESTS_VERSION}" \
        "semgrep==${SEMGREP_VERSION}" \
    && wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | sha256sum -c - \
    && tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks \
    && mv gitleaks /usr/local/bin/gitleaks \
    && rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && echo "${TRIVY_SHA256}  trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | sha256sum -c - \
    && tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy \
    && mv trivy /usr/local/bin/trivy \
    && rm "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && wget -q -O /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    && echo "${OSV_SCANNER_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c - \
    && chmod +x /usr/local/bin/osv-scanner \
    && npm install -g --ignore-scripts \
        "eslint@${ESLINT_VERSION}" \
        "eslint-plugin-security@${ESLINT_PLUGIN_SECURITY_VERSION}" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_PATH=/usr/local/lib/node_modules

WORKDIR /workspace
COPY scripts/ /scripts/

ENTRYPOINT ["python3", "/scripts/cli.py"]
