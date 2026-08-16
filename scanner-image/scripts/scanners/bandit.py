"""Bandit -> universal findings."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import subprocess

from .base import ScanResult

log = logging.getLogger(__name__)

_OUT = "/tmp/secureobs-bandit.json"


def _fp(*parts: str) -> str:
    s = "|".join(str(p or "") for p in parts).encode()
    return base64.b64encode(hashlib.sha256(s).digest()).decode().strip()


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    del config
    log.info("Running Bandit on %s", source_dir)

    proc = subprocess.run(
        [
            "bandit",
            "-r",
            source_dir,
            "-f",
            "json",
            "-o",
            _OUT,
            "-q",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):
        # Exit codes outside {0, 1} mean Bandit itself couldn't run — an
        # operational failure, not a legitimate skip. Previously this called
        # sys.exit(2), which raises SystemExit (a BaseException) and isn't
        # caught by cli.py's `except Exception:` handler — that silently
        # killed the entire `scan` subcommand, skipping every remaining
        # scanner and the infrastructure-analysis phase. Raise a plain
        # exception instead so cli.py's existing handler marks bandit's
        # status as "error" and continues on to the remaining scanners.
        stderr_tail = (proc.stderr or "")[:800]
        raise RuntimeError(
            f"bandit exited with unexpected code {proc.returncode}: {stderr_tail}"
        )

    if not os.path.exists(_OUT):
        return ScanResult(skipped=True, skip_reason="no bandit output file")

    with open(_OUT, encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results") or []
    findings: list[dict] = []

    for r in results:
        test_id = r.get("test_id") or "BANDIT"
        sev = (r.get("issue_severity") or "LOW").upper()
        if sev == "UNDEFINED":
            sev = "LOW"
        fn = r.get("filename") or ""
        line = r.get("line_number")
        code = (r.get("code") or "")[:4096]
        msg = r.get("issue_text") or test_id
        cwe = r.get("issue_cwe")
        cwe_ids = [f"CWE-{cwe.get('id')}"] if isinstance(cwe, dict) and cwe.get("id") else None

        fingerprint = _fp("bandit", test_id, fn, str(line), code[:200])

        findings.append(
            {
                "scanner": "bandit",
                "ruleId": test_id,
                "filePath": fn,
                "codeSnippet": code or None,
                "severity": sev,
                "description": msg,
                "cweIds": cwe_ids,
                "owaspCategories": None,
                "startLine": int(line) if line is not None else None,
                "endLine": int(line) if line is not None else None,
                "projectId": project_id,
                "pipelineRunId": pipeline_run_id,
                "fingerprint": fingerprint,
                "rawPayload": json.dumps(r, separators=(",", ":"))[:80_000],
            }
        )

    log.info("Bandit produced %d finding row(s)", len(findings))
    return ScanResult(findings=findings)
