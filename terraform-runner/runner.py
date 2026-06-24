#!/usr/bin/env python3
"""SecureObs managed credential-free Terraform analysis runner.

Runs inside an ephemeral, egress-limited container (Azure Container Instances).
It clones a user repository with a short-lived GitHub App installation token,
runs Checkov and the shared static HCL topology extractor, then uploads findings
and only the allowlisted topology to the SecureObs API.

Security contract
-----------------
* NEVER print the installation token, the SecureObs API key, or plan contents.
* Terraform is never initialized or executed and no cloud credentials are present.
* All work happens in an ephemeral temp dir; the container is destroyed after.

Exit codes
----------
0   Checkov findings and sanitized topology submitted successfully
2   a configuration / clone / analysis / submission failure (details on stderr)
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from urllib.parse import urlparse

# The shared sanitizer + API client are copied into /runner by the Dockerfile.
# Locally (tests / dev) they live in the sibling scanner-image source tree, so
# probe a few candidate roots and add the first that has the shared modules.
def _add_shared_modules_to_path() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        "/runner",
        here,
        os.path.join(here, "..", "scanner-image", "scripts"),
    ]
    for root in candidates:
        if os.path.isdir(os.path.join(root, "infrastructure")) and os.path.isfile(
            os.path.join(root, "api_client.py")
        ):
            sys.path.insert(0, os.path.abspath(root))
            return
    # Fall back to the container path; import will surface a clear error if absent.
    sys.path.insert(0, "/runner")


_add_shared_modules_to_path()
from infrastructure import terraform_config as iac_config  # noqa: E402
from scanners import checkov as checkov_scanner  # noqa: E402
import api_client  # noqa: E402

log = logging.getLogger("secureobs.terraform_runner")
SAFE_GIT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RunnerConfig:
    project_id: str
    tenant_id: str
    run_id: str
    repo_url: str
    ref: str
    terraform_root: str
    source_revision: str | None
    terraform_root_id: str | None
    var_files: list[str]
    api_url: str
    api_key: str
    installation_token: str


# ---------------------------------------------------------------------------
# Argument / environment parsing
# ---------------------------------------------------------------------------


def _parse_config(argv: list[str]) -> RunnerConfig:
    p = argparse.ArgumentParser(
        prog="secureobs-terraform-runner",
        description="Generate and submit a sanitized Terraform topology.",
    )
    p.add_argument("--project-id", required=True)
    p.add_argument("--tenant-id", required=True)
    p.add_argument("--run-id", required=True, help="SecureObs analysis run identifier")
    p.add_argument("--repo-url", required=True, help="HTTPS clone URL, e.g. https://github.com/owner/repo.git")
    p.add_argument("--ref", required=True, help="Branch, tag, or commit to plan")
    p.add_argument(
        "--terraform-root",
        default="",
        help="Path to the Terraform root within the repo (default: repo root)",
    )
    p.add_argument("--source-revision", default=None)
    p.add_argument("--terraform-root-id", default=None)
    p.add_argument(
        "--var-file",
        action="append",
        default=[],
        dest="var_files",
        help="Terraform-root-relative non-secret variable file used by static analysis (repeatable)",
    )
    args = p.parse_args(argv)

    # Secrets come from the environment, never the command line / process list.
    api_url = os.environ.get("SECUREOBS_API_URL", "").strip()
    api_key = os.environ.get("SECUREOBS_API_KEY", "").strip()
    token = os.environ.get("GITHUB_INSTALLATION_TOKEN", "").strip()

    missing = [
        name
        for name, val in (
            ("SECUREOBS_API_URL", api_url),
            ("SECUREOBS_API_KEY", api_key),
            ("GITHUB_INSTALLATION_TOKEN", token),
        )
        if not val
    ]
    if missing:
        raise SystemExit(f"Missing required environment variable(s): {', '.join(missing)}")

    parsed_repo = urlparse(args.repo_url)
    if (
        parsed_repo.scheme != "https" or
        parsed_repo.hostname != "github.com" or
        parsed_repo.username is not None or
        parsed_repo.password is not None or
        parsed_repo.query or
        parsed_repo.fragment or
        not re.fullmatch(
            r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git",
            parsed_repo.path,
        )
    ):
        raise SystemExit("--repo-url must be an HTTPS github.com repository URL.")
    if (
        not SAFE_GIT_REF_RE.fullmatch(args.ref) or
        ".." in args.ref or
        "//" in args.ref
    ):
        raise SystemExit("--ref contains unsupported characters.")

    return RunnerConfig(
        project_id=args.project_id,
        tenant_id=args.tenant_id,
        run_id=args.run_id,
        repo_url=args.repo_url,
        ref=args.ref,
        terraform_root=args.terraform_root.strip().strip("/"),
        source_revision=args.source_revision,
        terraform_root_id=args.terraform_root_id,
        var_files=list(args.var_files),
        api_url=api_url,
        api_key=api_key,
        installation_token=token,
    )


# ---------------------------------------------------------------------------
# Repository clone (token never appears in the URL or process list)
# ---------------------------------------------------------------------------


def clone_repo(cfg: RunnerConfig, work_dir: str) -> str:
    """Fetch one branch, tag, or reachable commit using an HTTP auth header."""
    clone_dir = os.path.join(work_dir, "repo")
    basic = base64.b64encode(f"x-access-token:{cfg.installation_token}".encode()).decode()
    # Pass the header through Git's one-shot environment configuration. This keeps the
    # token out of argv, logs, and the remote URL persisted in .git/config.
    env = os.environ.copy()
    env.update({
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.extraHeader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        "GIT_TERMINAL_PROMPT": "0",
    })
    commands = [
        ["git", "init", "--quiet", clone_dir],
        ["git", "-C", clone_dir, "remote", "add", "origin", cfg.repo_url],
        ["git", "-C", clone_dir, "fetch", "--quiet", "--depth", "1", "origin", cfg.ref],
        ["git", "-C", clone_dir, "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]
    for command in commands:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, env=env)
        if result.returncode != 0:
            stderr = _scrub(result.stderr, cfg.installation_token)
            raise RuntimeError(f"git fetch failed: {stderr.strip()[:400]}")
    return clone_dir


def _cloned_revision(clone_dir: str, fallback: str | None) -> str | None:
    result = subprocess.run(
        ["git", "-C", clone_dir, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    revision = result.stdout.strip()
    return revision if result.returncode == 0 and revision else fallback


def _scrub(text: str, *secrets: str) -> str:
    out = text
    for s in secrets:
        if s:
            out = out.replace(s, "***")
    return out


# ---------------------------------------------------------------------------
# Terraform root resolution
# ---------------------------------------------------------------------------


def _resolve_root(clone_dir: str, terraform_root: str) -> str:
    root = os.path.realpath(os.path.join(clone_dir, terraform_root))
    base = os.path.realpath(clone_dir)
    if os.path.commonpath([root, base]) != base:
        raise RuntimeError("Terraform root path escapes the repository.")
    if not os.path.isdir(root):
        raise RuntimeError(f"Terraform root not found: {terraform_root or '<repo root>'}")
    return root


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    try:
        cfg = _parse_config(argv)
    except SystemExit as exc:
        # argparse / validation failures.
        if isinstance(exc.code, str):
            log.error("%s", exc.code)
            _emit_status(False, error=str(exc.code))
            return 2
        raise

    work_dir = tempfile.mkdtemp(prefix="secureobs-iac-")
    try:
        clone_dir = clone_repo(cfg, work_dir)
        root_dir = _resolve_root(clone_dir, cfg.terraform_root)
        source_revision = _cloned_revision(clone_dir, cfg.source_revision)

        # Checkov complements the custom graph rules with its broader Terraform
        # misconfiguration policy set. Findings are stored first so graph ingestion can
        # correlate them to Terraform resource addresses in the same run.
        checkov_result = checkov_scanner.run(
            root_dir,
            cfg.project_id,
            cfg.run_id,
            {"terraform_root": root_dir},
        )
        if checkov_result.skipped:
            raise RuntimeError(
                checkov_result.skip_reason or "Checkov Terraform analysis failed")
        if checkov_result.findings:
            try:
                api_client.post_findings(
                    cfg.api_url,
                    cfg.api_key,
                    "findings/bulk-universal",
                    checkov_result.findings,
                )
            except SystemExit as exc:
                raise RuntimeError("Checkov findings submission failed") from exc

        # Credential-free static analysis: parse the HCL directly (no terraform, no plan,
        # no cloud credentials) and submit only the allowlisted topology.
        result = iac_config.run(
            root_dir=root_dir,
            project_id=cfg.project_id,
            pipeline_run_id=cfg.run_id,
            source_revision=source_revision,
            terraform_root_id=cfg.terraform_root_id,
            var_files=cfg.var_files,
            api_url=cfg.api_url,
            api_key=cfg.api_key,
            require_submission=True,
        )
        if not result.success:
            log.error("Infrastructure analysis failed: %s", result.error)
            _emit_status(False, error=result.error or "analysis failed")
            return 2

        log.info(
            "Analysis submitted: %d resource(s), %d edge(s), %d path(s)",
            result.resource_count,
            result.edge_count,
            result.path_count,
        )
        _emit_status(
            True,
            resource_count=result.resource_count,
            edge_count=result.edge_count,
            path_count=result.path_count,
            unsupported_count=result.unsupported_count,
        )
        return 0
    except Exception as exc:  # noqa: BLE001 — single top-level failure boundary
        # cfg is always bound here: parse failures return before this block.
        msg = _scrub(str(exc), cfg.installation_token, cfg.api_key)
        log.error("Runner failed: %s", msg)
        _emit_status(False, error=msg[:500])
        return 2
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _emit_status(success: bool, **fields) -> None:
    """Print a single-line JSON status the API monitor can parse from the log tail."""
    payload = {"secureobsRunnerStatus": "succeeded" if success else "failed", **fields}
    print(json.dumps(payload), flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
