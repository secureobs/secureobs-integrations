"""Checkov -> universal findings (best-effort JSON parse across versions)."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile

from .base import ScanResult

log = logging.getLogger(__name__)
CHECKOV_TIMEOUT_SECONDS = 15 * 60


def _fp(*parts: str) -> str:
    s = "|".join(str(p or "") for p in parts).encode()
    return base64.b64encode(hashlib.sha256(s).digest()).decode().strip()


def _iter_failed_checks(obj) -> list[dict]:
    """Extract failed_checks from nested Checkov JSON."""
    out: list[dict] = []
    if obj is None:
        return out
    if isinstance(obj, list):
        for item in obj:
            out.extend(_iter_failed_checks(item))
        return out
    if isinstance(obj, dict):
        fc = obj.get("failed_checks")
        if isinstance(fc, list):
            for c in fc:
                if isinstance(c, dict):
                    out.append(c)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                out.extend(_iter_failed_checks(v))
    return out


def _build_command(
    source_dir: str,
    output_dir: str,
    config: dict[str, str] | None,
) -> list[str]:
    """Build a Terraform-focused Checkov command for source or plan analysis."""
    cfg = config or {}
    terraform_root = cfg.get("terraform_root") or source_dir
    plan_json = cfg.get("terraform_plan_json")

    command = ["checkov"]
    if plan_json:
        command.extend(["-f", plan_json])
        if terraform_root:
            command.extend([
                "--repo-root-for-plan-enrichment",
                terraform_root,
                "--deep-analysis",
            ])
    else:
        command.extend(["-d", terraform_root, "--framework", "terraform"])

    command.extend([
        "--quiet",
        "-o",
        "json",
        "--output-file-path",
        output_dir,
    ])
    return command


def _safe_raw_payload(check: dict, check_id: str, name: str, severity: str) -> dict:
    """Retain correlation metadata without source blocks or evaluated values."""
    evaluated_keys = check.get("evaluated_keys") or []
    line_range = check.get("file_line_range")
    safe_line_range: list[int] | None = None
    if isinstance(line_range, list):
        safe_line_range = []
        for value in line_range[:2]:
            try:
                safe_line_range.append(int(value))
            except (TypeError, ValueError):
                pass
        if not safe_line_range:
            safe_line_range = None
    resource = check.get("resource")
    resource_address = check.get("resource_address")
    return {
        "check_id": str(check_id)[:256],
        "check_name": str(name)[:1024],
        "resource": str(resource)[:1024] if isinstance(resource, str) else None,
        "resource_address": (
            str(resource_address)[:1024]
            if isinstance(resource_address, str)
            else None
        ),
        "file_path": str(check.get("file_path") or "")[:2048],
        "file_line_range": safe_line_range,
        "severity": severity,
        "guideline": str(check.get("guideline") or "")[:2048] or None,
        "evaluated_keys": [
            str(key)[:128]
            for key in evaluated_keys
            if isinstance(key, (str, int))
        ][:32],
    }


def _normalize_file_path(file_path: object, terraform_root: str) -> str:
    raw = str(file_path or "").replace("\\", "/")
    if not raw:
        return ""
    root = os.path.realpath(terraform_root)
    candidate = os.path.realpath(raw)
    if candidate == root:
        return "."
    if candidate.startswith(root + os.sep):
        return os.path.relpath(candidate, root).replace("\\", "/")
    # Checkov commonly emits root-relative paths with a leading slash.
    return raw.lstrip("/")


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    cfg = config or {}
    target = cfg.get("terraform_plan_json") or cfg.get("terraform_root") or source_dir
    log.info("Running Checkov Terraform analysis on %s", target)

    tmpdir = tempfile.mkdtemp(prefix="secureobs-checkov-")
    data = None

    try:
        proc = subprocess.run(
            _build_command(source_dir, tmpdir, cfg),
            capture_output=True,
            text=True,
            timeout=CHECKOV_TIMEOUT_SECONDS,
        )
        if proc.returncode not in (0, 1):
            log.error(
                "Checkov exited %d: %s",
                proc.returncode,
                (proc.stderr or proc.stdout or "")[:800],
            )
            return ScanResult(
                skipped=True,
                skip_reason="Checkov Terraform analysis failed",
                exit_code=proc.returncode,
                stderr_tail=(proc.stderr or proc.stdout or "")[-2000:],
            )

        results_path = os.path.join(tmpdir, "results.json")
        if os.path.isfile(results_path):
            with open(results_path, encoding="utf-8") as f:
                data = json.load(f)
        elif proc.stdout.strip():
            data = json.loads(proc.stdout)
        else:
            json_files = [
                os.path.join(tmpdir, f)
                for f in os.listdir(tmpdir)
                if f.endswith(".json") and "checkov" not in f.lower()
            ]
            if json_files:
                with open(json_files[0], encoding="utf-8") as f:
                    data = json.load(f)

    except subprocess.TimeoutExpired:
        log.error(
            "Checkov exceeded the %d-second execution limit.",
            CHECKOV_TIMEOUT_SECONDS,
        )
        return ScanResult(
            skipped=True,
            skip_reason="Checkov Terraform analysis timed out",
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if data is None:
        return ScanResult(skipped=True, skip_reason="checkov wrote no JSON")

    failed = _iter_failed_checks(data)

    findings: list[dict] = []
    for c in failed:
        cid = str(c.get("check_id") or "CKV")[:256]
        sev_raw = str(
            c.get("severity") or c.get("Check_Severity") or "MEDIUM")[:32]
        name = str(c.get("check_name") or cid)[:1024]
        fpath = _normalize_file_path(
            c.get("file_path"),
            str(cfg.get("terraform_root") or source_dir),
        )
        rl = c.get("file_line_range")
        start = end_line = None
        if isinstance(rl, list) and len(rl) >= 1:
            try:
                start = int(rl[0])
            except (ValueError, TypeError):
                start = None
            if len(rl) >= 2:
                try:
                    end_line = int(rl[1])
                except (ValueError, TypeError):
                    end_line = start

        desc = "\n".join(
            filter(
                None,
                [
                    name,
                    str(c.get("guideline") or "")[:2048],
                    str(c.get("resource") or c.get("check_class") or "")[:1024],
                ],
            )
        )[:4096]

        resource_address = c.get("resource_address") or c.get("resource") or ""
        fingerprint = _fp(
            "checkov", cid, str(resource_address), str(fpath), str(start))
        safe_raw = _safe_raw_payload(c, cid, name, sev_raw.upper())

        findings.append(
            {
                "scanner": "checkov",
                "ruleId": cid,
                "filePath": str(fpath) or None,
                "codeSnippet": None,
                "severity": sev_raw.upper(),
                "description": desc or cid,
                "cweIds": None,
                "owaspCategories": None,
                "startLine": start,
                "endLine": end_line or start,
                "projectId": project_id,
                "pipelineRunId": pipeline_run_id,
                "fingerprint": fingerprint,
                "rawPayload": json.dumps(safe_raw, separators=(",", ":")),
            }
        )

    log.info("Checkov produced %d finding row(s)", len(findings))
    return ScanResult(findings=findings)
