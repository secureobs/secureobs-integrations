FROM python:3.12-slim
LABEL maintainer="Jason Achkar Diab"

ARG TRIVY_VERSION=0.70.0
ARG OSV_SCANNER_VERSION=v1.9.2

RUN apt-get update && apt-get install -y --no-install-recommends \
        git wget ca-certificates curl \
        nodejs npm \
    && pip install --no-cache-dir semgrep requests bandit checkov \
    && wget -q "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz" \
    && tar -xzf gitleaks_8.21.2_linux_x64.tar.gz gitleaks \
    && mv gitleaks /usr/local/bin/gitleaks \
    && rm gitleaks_8.21.2_linux_x64.tar.gz \
    && wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy \
    && mv trivy /usr/local/bin/trivy \
    && rm "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && wget -q -O /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    && chmod +x /usr/local/bin/osv-scanner \
    && npm install -g eslint@8.57.0 eslint-plugin-security@2.1.1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_PATH=/usr/local/lib/node_modules

WORKDIR /workspace
COPY scripts/ /scripts/

ENTRYPOINT ["python3", "/scripts/cli.py"]
