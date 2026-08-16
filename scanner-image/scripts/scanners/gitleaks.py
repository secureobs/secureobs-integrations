import json
import logging
import os
import subprocess

from .base import ScanResult

log = logging.getLogger(__name__)

_RESULTS_FILE = "/tmp/secureobs-gitleaks.json"


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: "dict[str, str] | None" = None,
) -> ScanResult:
    # ``config`` is reserved for per-project tuning (custom rules, allowlists).
    # GitLeaks currently runs with the bundled default ruleset for everyone.
    del config

    log.info("Running GitLeaks on %s", source_dir)

    proc = subprocess.run(
        [
            "gitleaks", "detect",
            "--source", source_dir,
            "--report-format", "json",
            "--report-path", _RESULTS_FILE,
            "--no-git",
        ],
        capture_output=True,
        text=True,
    )

    # gitleaks exits 0 (clean) or 1 (secrets found) — both are success.
    # Any other code means GitLeaks itself couldn't run — an operational
    # failure. Previously this called sys.exit(2), which raises SystemExit
    # (a BaseException) and isn't caught by cli.py's `except Exception:`
    # handler — that silently killed the entire `scan` subcommand, skipping
    # every remaining scanner. Raise a plain exception instead so cli.py's
    # existing handler marks gitleaks' status as "error" and continues on.
    if proc.returncode not in (0, 1):
        stderr_tail = (proc.stderr or "")[:500]
        raise RuntimeError(
            f"gitleaks exited with unexpected code {proc.returncode}: {stderr_tail}"
        )

    if not os.path.exists(_RESULTS_FILE):
        log.info("GitLeaks produced no results file — treating as clean.")
        return ScanResult(skipped=True, skip_reason="no results file")

    with open(_RESULTS_FILE, encoding="utf-8") as f:
        raw = f.read().strip()

    if not raw or raw == "null":
        log.info("GitLeaks: no secrets found.")
        return ScanResult()

    data = json.loads(raw)
    if not data:
        log.info("GitLeaks: no secrets found.")
        return ScanResult()

    log.info("GitLeaks found %d secret(s)", len(data))

    findings = []
    for item in data:
        findings.append({
            "ruleId": item.get("RuleID", ""),
            "description": item.get("Description", ""),
            "file": item.get("File", ""),
            "startLine": item.get("StartLine", 0),
            "endLine": item.get("EndLine", 0),
            "fingerprint": item.get("Fingerprint", ""),
            "match": item.get("Match", ""),
            "projectId": project_id,
            "pipelineRunId": pipeline_run_id,
        })

    return ScanResult(findings=findings)
