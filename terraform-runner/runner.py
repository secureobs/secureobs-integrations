#!/usr/bin/env python3
"""SecureObs managed Terraform plan runner.

Runs inside an ephemeral, egress-limited container (Azure Container Instances).
It clones a user repository with a short-lived GitHub App installation token,
generates a Terraform plan WITHOUT backend state or a resource refresh, then
hands the plan JSON to the shared sanitizer (``infrastructure.terraform_plan``)
which uploads only an allowlisted topology to the SecureObs API. The raw plan
never leaves this container.

Security contract
-----------------
* NEVER print the installation token, the SecureObs API key, or plan contents.
* The plan runs with ``-refresh=false -backend=false`` and NO cloud credentials,
  so it never reads remote state or touches deployed resources.
* All work happens in an ephemeral temp dir; the container is destroyed after.
* The Terraform binary is downloaded over TLS and verified against HashiCorp's
  GPG-signed SHA256SUMS before use.

Exit codes
----------
0   plan generated, sanitized, and submitted successfully
2   a configuration / clone / plan / submission failure (details on stderr)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass

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
from infrastructure import terraform_plan as iac_plan  # noqa: E402

log = logging.getLogger("secureobs.terraform_runner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TERRAFORM_VERSION = "1.9.8"
TERRAFORM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
RELEASES_BASE = "https://releases.hashicorp.com/terraform"
# HashiCorp's published code-signing key fingerprint (C874 011F 0AB4 0511 0D02
# 1055 3436 5D94 72D7 468F). The SHA256SUMS signature is verified against this
# exact fingerprint before any checksum is trusted.
HASHICORP_GPG_FINGERPRINT = "C874011F0AB405110D02105534365D9472D7468F"
PLAN_JSON_NAME = "tfplan.json"
PLAN_BINARY_NAME = "tfplan.binary"
DOWNLOAD_TIMEOUT = 120
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MiB ceiling for the terraform zip


@dataclass(frozen=True)
class RunnerConfig:
    project_id: str
    tenant_id: str
    run_id: str
    repo_url: str
    ref: str
    terraform_root: str
    terraform_version: str
    source_revision: str | None
    terraform_root_id: str | None
    var_files: list[str]
    extra_vars: list[str]
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
    p.add_argument("--terraform-version", default=DEFAULT_TERRAFORM_VERSION)
    p.add_argument("--source-revision", default=None)
    p.add_argument("--terraform-root-id", default=None)
    p.add_argument(
        "--var-file",
        action="append",
        default=[],
        dest="var_files",
        help="Repo-relative var file passed to terraform plan (repeatable)",
    )
    p.add_argument(
        "--var",
        action="append",
        default=[],
        dest="extra_vars",
        help="KEY=VALUE passed to terraform plan as -var (repeatable)",
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

    if not TERRAFORM_VERSION_RE.match(args.terraform_version):
        raise SystemExit(
            f"Invalid --terraform-version {args.terraform_version!r}; expected X.Y.Z."
        )

    return RunnerConfig(
        project_id=args.project_id,
        tenant_id=args.tenant_id,
        run_id=args.run_id,
        repo_url=args.repo_url,
        ref=args.ref,
        terraform_root=args.terraform_root.strip().strip("/"),
        terraform_version=args.terraform_version,
        source_revision=args.source_revision,
        terraform_root_id=args.terraform_root_id,
        var_files=list(args.var_files),
        extra_vars=list(args.extra_vars),
        api_url=api_url,
        api_key=api_key,
        installation_token=token,
    )


# ---------------------------------------------------------------------------
# Terraform binary acquisition (download + GPG-verified checksum)
# ---------------------------------------------------------------------------


def _download(url: str, dest: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "secureobs-terraform-runner"})
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:  # noqa: S310 (https only)
        if resp.status != 200:
            raise RuntimeError(f"GET {url} returned HTTP {resp.status}")
        total = 0
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(f"Download exceeded {MAX_DOWNLOAD_BYTES} bytes: {url}")
                fh.write(chunk)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def ensure_terraform(version: str, work_dir: str) -> str:
    """Download, verify, and unpack terraform <version>; return the binary path.

    Verification chain: the zip is checked against SHA256SUMS, and SHA256SUMS is
    GPG-verified against HashiCorp's pinned signing key. Any failure aborts.
    """
    base = f"{RELEASES_BASE}/{version}"
    zip_name = f"terraform_{version}_linux_amd64.zip"
    sums_name = f"terraform_{version}_SHA256SUMS"
    sig_name = f"{sums_name}.sig"

    dl = os.path.join(work_dir, "tf-download")
    os.makedirs(dl, exist_ok=True)
    zip_path = os.path.join(dl, zip_name)
    sums_path = os.path.join(dl, sums_name)
    sig_path = os.path.join(dl, sig_name)

    log.info("Fetching Terraform %s", version)
    _download(f"{base}/{zip_name}", zip_path)
    _download(f"{base}/{sums_name}", sums_path)
    _download(f"{base}/{sig_name}", sig_path)

    # 1. GPG-verify the checksum file against HashiCorp's pinned key.
    verify = subprocess.run(
        ["gpg", "--status-fd", "1", "--verify", sig_path, sums_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if verify.returncode != 0 or HASHICORP_GPG_FINGERPRINT not in verify.stdout.replace(" ", ""):
        raise RuntimeError("Terraform SHA256SUMS signature verification failed.")

    # 2. Verify the downloaded zip against the (now-trusted) checksum file.
    want = None
    with open(sums_path, "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 2 and parts[1] == zip_name:
                want = parts[0].lower()
                break
    if not want:
        raise RuntimeError(f"{zip_name} not present in SHA256SUMS.")
    got = _sha256(zip_path)
    if got != want:
        raise RuntimeError("Terraform zip checksum mismatch.")

    # 3. Unpack.
    out_dir = os.path.join(work_dir, "tf-bin")
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extract("terraform", out_dir)
    binary = os.path.join(out_dir, "terraform")
    os.chmod(binary, 0o755)
    log.info("Terraform %s verified and ready", version)
    return binary


# ---------------------------------------------------------------------------
# Repository clone (token never appears in the URL or process list)
# ---------------------------------------------------------------------------


def clone_repo(cfg: RunnerConfig, work_dir: str) -> str:
    """Shallow-clone the repo at cfg.ref using an HTTP auth header; return path."""
    clone_dir = os.path.join(work_dir, "repo")
    basic = base64.b64encode(f"x-access-token:{cfg.installation_token}".encode()).decode()
    # The header is passed via -c so the token is not part of argv of `clone`
    # itself, and never part of the remote URL stored in .git/config.
    cmd = [
        "git",
        "-c",
        f"http.extraheader=AUTHORIZATION: basic {basic}",
        "clone",
        "--depth",
        "1",
        "--branch",
        cfg.ref,
        "--single-branch",
        cfg.repo_url,
        clone_dir,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        # Scrub anything token-shaped from surfaced output.
        stderr = _scrub(result.stderr, cfg.installation_token)
        raise RuntimeError(f"git clone failed: {stderr.strip()[:400]}")
    return clone_dir


def _scrub(text: str, *secrets: str) -> str:
    out = text
    for s in secrets:
        if s:
            out = out.replace(s, "***")
    return out


# ---------------------------------------------------------------------------
# Terraform plan generation
# ---------------------------------------------------------------------------


def _resolve_root(clone_dir: str, terraform_root: str) -> str:
    root = os.path.realpath(os.path.join(clone_dir, terraform_root))
    base = os.path.realpath(clone_dir)
    if os.path.commonpath([root, base]) != base:
        raise RuntimeError("Terraform root path escapes the repository.")
    if not os.path.isdir(root):
        raise RuntimeError(f"Terraform root not found: {terraform_root or '<repo root>'}")
    return root


def _run_terraform(binary: str, root: str, args: list[str], env: dict) -> None:
    result = subprocess.run(
        [binary, f"-chdir={root}", *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        # Terraform errors can echo variable names but not values; still cap length.
        raise RuntimeError(
            f"terraform {args[0]} failed: {result.stderr.strip()[:600] or result.stdout.strip()[:600]}"
        )


def generate_plan_json(cfg: RunnerConfig, binary: str, clone_dir: str, work_dir: str) -> str:
    """Run init + plan + show; return an absolute path to the plan JSON."""
    root = _resolve_root(clone_dir, cfg.terraform_root)

    # Drop any committed backend config; we plan with -backend=false regardless.
    backend = os.path.join(root, "backend.tf")
    if os.path.isfile(backend):
        os.remove(backend)

    # Static analysis must never auto-register Azure providers or read state.
    env = dict(os.environ)
    env["ARM_SKIP_PROVIDER_REGISTRATION"] = "true"
    env["TF_IN_AUTOMATION"] = "1"
    env["TF_INPUT"] = "0"
    # Ensure no inherited cloud credentials leak into the plan.
    for var in ("ARM_CLIENT_SECRET", "ARM_CLIENT_ID", "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID"):
        env.pop(var, None)

    # The committed .terraform.lock.hcl often only carries hashes for the developer's
    # platform, so init would fail on this linux_amd64 container with "doesn't match any
    # of the checksums". Record the linux provider checksums first (preserving the locked
    # versions). Best-effort: if it fails (e.g. no lock file yet), init still proceeds.
    try:
        _run_terraform(binary, root, ["providers", "lock", "-platform=linux_amd64"], env)
    except RuntimeError as exc:
        log.info("providers lock skipped: %s", str(exc)[:200])

    _run_terraform(binary, root, ["init", "-backend=false", "-input=false", "-no-color"], env)

    plan_args = [
        "plan",
        "-refresh=false",
        "-lock=false",
        "-input=false",
        "-no-color",
        f"-out={PLAN_BINARY_NAME}",
    ]
    for vf in cfg.var_files:
        plan_args.append(f"-var-file={vf}")
    for kv in cfg.extra_vars:
        plan_args.append(f"-var={kv}")
    _run_terraform(binary, root, plan_args, env)

    # `show -json` writes to stdout; capture it to a file inside work_dir so the
    # sanitizer's workspace-bounded path validation accepts it.
    plan_json_path = os.path.join(work_dir, PLAN_JSON_NAME)
    show = subprocess.run(
        [binary, f"-chdir={root}", "show", "-json", PLAN_BINARY_NAME],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if show.returncode != 0:
        raise RuntimeError(f"terraform show failed: {show.stderr.strip()[:400]}")
    with open(plan_json_path, "w", encoding="utf-8") as fh:
        fh.write(show.stdout)
    return plan_json_path


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
        binary = ensure_terraform(cfg.terraform_version, work_dir)
        clone_dir = clone_repo(cfg, work_dir)
        plan_json_path = generate_plan_json(cfg, binary, clone_dir, work_dir)

        # Hand off to the shared, graph-compatible sanitizer + submitter.
        rel = os.path.relpath(plan_json_path, work_dir)
        result = iac_plan.run(
            workspace=work_dir,
            project_id=cfg.project_id,
            pipeline_run_id=cfg.run_id,
            plan_json_relative_path=rel,
            source_revision=cfg.source_revision,
            terraform_root_id=cfg.terraform_root_id,
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
