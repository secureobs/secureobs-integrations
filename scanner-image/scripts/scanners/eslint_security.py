"""eslint-plugin-security -> universal findings (plain JS/Node projects)."""
from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from .base import ScanResult

log = logging.getLogger(__name__)

CFG = "/scripts/eslint-secureobs.json"


def _workspace_has_js(workspace: str) -> bool:
    suffixes = {".js", ".jsx", ".mjs", ".cjs"}
    root = Path(workspace)
    if not root.is_dir():
        return False

    for i, path in enumerate(root.rglob("*")):
        if i > 8000:
            break
        if path.is_file() and path.suffix.lower() in suffixes:
            return True
    return False


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    del config
    if not _workspace_has_js(source_dir):
        log.info("No JavaScript files found — skipping eslint-security.")
        return ScanResult(skipped=True, skip_reason="no_js_files")

    if not os.path.isfile(CFG):
        log.error("Missing ESLint config at %s", CFG)
        return ScanResult(skipped=True, skip_reason="missing_eslint_config")

    log.info("Running ESLint (security plugin) on %s", source_dir)

    proc = subprocess.run(
        [
            "eslint",
            ".",
            "--no-error-on-unmatched-pattern",
            "--config",
            CFG,
            "--ext",
            ".js,.jsx,.mjs,.cjs",
            "--format",
            "json",
        ],
        cwd=source_dir,
        capture_output=True,
        text=True,
    )

    if proc.returncode not in (0, 1):
        # Exit codes outside {0, 1} mean ESLint itself couldn't run (bad
        # config, missing plugin, crash, etc.) — an operational failure, not
        # a legitimate "nothing to scan" skip. Raise so cli.py's exception
        # handler marks this scanner's status as "error" (not "skipped")
        # and continues on to the remaining scanners.
        stderr_tail = (proc.stderr or "")[-500:]
        raise RuntimeError(
            f"eslint exited with unexpected code {proc.returncode}: {stderr_tail}"
        )

    raw = proc.stdout.strip()
    if not raw or raw == "[]":
        return ScanResult(findings=[])

    try:
        files = json.loads(raw)
    except json.JSONDecodeError as exc:
        # ESLint ran but produced untrustworthy output — also an operational
        # failure, not a legitimate skip.
        raise RuntimeError(f"eslint produced invalid JSON output: {exc}") from exc

    findings: list[dict] = []
    for entry in files:
        fpath = entry.get("filePath") or ""
        for msg in entry.get("messages") or []:
            rule_id = msg.get("ruleId") or "ESLINT"
            sev_raw = str(msg.get("severity") or 1)
            # ESLint severity: 1=warn, 2=error — map loosely
            if sev_raw == "2":
                sev = "HIGH"
            elif sev_raw == "1":
                sev = "MEDIUM"
            else:
                sev = "LOW"

            desc = msg.get("message") or rule_id
            line = msg.get("line")
            end_line = msg.get("endLine")

            findings.append(
                {
                    "scanner": "eslint-security",
                    "ruleId": rule_id,
                    "filePath": fpath,
                    "codeSnippet": None,
                    "severity": sev,
                    "description": desc,
                    "cweIds": None,
                    "owaspCategories": None,
                    "startLine": int(line) if line is not None else None,
                    "endLine": int(end_line) if end_line is not None else None,
                    "projectId": project_id,
                    "pipelineRunId": pipeline_run_id,
                    "fingerprint": None,
                    "rawPayload": json.dumps(msg, separators=(",", ":"))[:40_000],
                }
            )

    log.info("ESLint produced %d finding row(s)", len(findings))
    return ScanResult(findings=findings)
