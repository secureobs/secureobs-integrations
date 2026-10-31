"""Disposable, deliberately vulnerable multi-ecosystem project for SCA tests.

The manifests are written to a temporary directory at test time instead of being
committed as real lockfiles, so GitHub's dependency graph, Dependabot and the
dogfood self-scan never treat them as this repository's dependencies.

Every pinned version below has at least one published advisory, chosen so the
real Trivy / OSV-Scanner integration tests can assert on stable, well-known IDs:

  npm     lodash 4.17.20 (GHSA-35jh-r3h4-6jhm / CVE-2021-23337, fixed 4.17.21)
          lodash 4.17.15 nested under async (a second, separately vulnerable version)
          async 2.6.3 (CVE-2021-43138, fixed 2.6.4)
          minimist 1.2.5 (dev dependency, CVE-2021-44906)
  PyPI    requests 2.19.0 (CVE-2018-18074), PyYAML 5.3 (CVE-2020-14343)
          urllib3 1.26.4 via poetry.lock (CVE-2021-33503)
  NuGet   Newtonsoft.Json 12.0.1 (GHSA-5crp-9r3c-p9vr, direct)
          System.Text.Encodings.Web 4.5.0 (CVE-2021-26701, transitive)
  Maven   org.apache.logging.log4j:log4j-core 2.14.1 (CVE-2021-44228)
  Gradle  com.fasterxml.jackson.core:jackson-databind 2.9.8 (many CVEs)
  Go      golang.org/x/text v0.3.5 (CVE-2021-38561)

It also contains one Dockerfile misconfiguration and one fake credential so the
Trivy "mixed output" path (vuln + misconfig + secret) is exercised for real.
"""
from __future__ import annotations

import json
from pathlib import Path


def _npm_lock() -> dict:
    return {
        "name": "secureobs-sca-fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "secureobs-sca-fixture",
                "version": "1.0.0",
                "dependencies": {"async": "2.6.3", "lodash": "4.17.20"},
                "devDependencies": {"minimist": "1.2.5"},
            },
            "node_modules/async": {
                "version": "2.6.3",
                "resolved": "https://registry.npmjs.org/async/-/async-2.6.3.tgz",
                "dependencies": {"lodash": "^4.17.14"},
            },
            "node_modules/async/node_modules/lodash": {
                "version": "4.17.15",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
            },
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
            },
            "node_modules/minimist": {
                "version": "1.2.5",
                "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
                "dev": True,
            },
        },
    }


def _npm_package_json() -> dict:
    return {
        "name": "secureobs-sca-fixture",
        "version": "1.0.0",
        "dependencies": {"async": "2.6.3", "lodash": "4.17.20"},
        "devDependencies": {"minimist": "1.2.5"},
    }


_REQUIREMENTS = "requests==2.19.0\nPyYAML==5.3\n"

_PYPROJECT = """[tool.poetry]
name = "worker"
version = "0.1.0"
description = "SecureObs SCA fixture"
authors = ["SecureObs <fixtures@secureobs.invalid>"]

[tool.poetry.dependencies]
python = "^3.9"
urllib3 = "1.26.4"
"""

_POETRY_LOCK = """[[package]]
name = "urllib3"
version = "1.26.4"
description = "HTTP library with thread-safe connection pooling, file post, and more."
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.9"
content-hash = "0000000000000000000000000000000000000000000000000000000000000000"
"""


def _nuget_lock() -> dict:
    return {
        "version": 1,
        "dependencies": {
            "net8.0": {
                "Newtonsoft.Json": {
                    "type": "Direct",
                    "requested": "[12.0.1, )",
                    "resolved": "12.0.1",
                    "contentHash": "pBR3wCgYWZGiaZDYP+HHYnalVnPJlpP1q55qvVb+adrDHmFMDc1NAKio61xTwftK3Pw5h7TZJPJEEVMd6ty8rg==",
                },
                "System.Text.Encodings.Web": {
                    "type": "Transitive",
                    "resolved": "4.5.0",
                    "contentHash": "Xg4G4Indi4dqP1iuAiMSwpiWS54ZghzR644OtsRCm/m/lBMG8dUBhLVN7hLm8NNrNTR+iGbshCPTwrvxZPlm4g==",
                },
            }
        },
    }


_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  </ItemGroup>
</Project>
"""

_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>sca-fixture</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
"""

_GRADLE_LOCK = """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath
empty=
"""

_GO_MOD = """module example.com/secureobs/fixture

go 1.21

require golang.org/x/text v0.3.5
"""

_GO_SUM = """golang.org/x/text v0.3.5 h1:i6eZZ+zk0SOf0xgBpEpPD18qWcJda6q1sxt3S0kzyUQ=
golang.org/x/text v0.3.5/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
"""

_DOCKERFILE = """FROM node:latest
COPY . /app
RUN npm ci
CMD ["node", "/app/index.js"]
"""


def _fake_github_token() -> str:
    # Assembled at runtime so the literal token never appears in this repository
    # (secret scanners running over the source must not flag the fixture itself).
    return "ghp" + "_" + "SecureObsFixture" + "0123456789" + "abcdefghij"


def write_vulnerable_project(root: Path, *, include_secret: bool = True,
                             include_misconfig: bool = True) -> Path:
    """Write the fixture project under ``root`` and return ``root``."""
    root.mkdir(parents=True, exist_ok=True)

    web = root / "web"
    web.mkdir(exist_ok=True)
    (web / "package.json").write_text(json.dumps(_npm_package_json(), indent=2), encoding="utf-8")
    (web / "package-lock.json").write_text(json.dumps(_npm_lock(), indent=2), encoding="utf-8")

    (root / "requirements.txt").write_text(_REQUIREMENTS, encoding="utf-8")

    worker = root / "services" / "worker"
    worker.mkdir(parents=True, exist_ok=True)
    (worker / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    (worker / "poetry.lock").write_text(_POETRY_LOCK, encoding="utf-8")

    api = root / "src" / "Api"
    api.mkdir(parents=True, exist_ok=True)
    (api / "Api.csproj").write_text(_CSPROJ, encoding="utf-8")
    (api / "packages.lock.json").write_text(json.dumps(_nuget_lock(), indent=2), encoding="utf-8")

    java = root / "java"
    java.mkdir(exist_ok=True)
    (java / "pom.xml").write_text(_POM, encoding="utf-8")
    (java / "gradle.lockfile").write_text(_GRADLE_LOCK, encoding="utf-8")

    go = root / "go-svc"
    go.mkdir(exist_ok=True)
    (go / "go.mod").write_text(_GO_MOD, encoding="utf-8")
    (go / "go.sum").write_text(_GO_SUM, encoding="utf-8")

    if include_misconfig:
        (root / "Dockerfile").write_text(_DOCKERFILE, encoding="utf-8")

    if include_secret:
        config = root / "config"
        config.mkdir(exist_ok=True)
        (config / "ci.env").write_text(f"GITHUB_TOKEN={_fake_github_token()}\n", encoding="utf-8")

    return root


def write_project_without_manifests(root: Path) -> Path:
    """A project with source code but no dependency manifests or lockfiles."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("# No dependencies here\n", encoding="utf-8")
    (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
    return root


if __name__ == "__main__":  # pragma: no cover - manual fixture regeneration helper
    import sys

    target = Path(sys.argv[1] if len(sys.argv) > 1 else "/workspace")
    write_vulnerable_project(target)
    print(f"Fixture project written to {target}")
