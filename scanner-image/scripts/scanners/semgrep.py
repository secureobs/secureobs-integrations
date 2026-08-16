import json
import logging
import os
import subprocess

from .base import ScanResult

log = logging.getLogger(__name__)

_RESULTS_FILE = "/tmp/secureobs-semgrep.json"


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: "dict[str, str] | None" = None,
) -> ScanResult:
    # ``config`` is reserved for per-project tuning (custom rulesets, exclude
    # globs, etc.). Semgrep currently runs the canonical p/ci ruleset for
    # everyone — once we surface knobs in the dashboard we'll read them here.
    del config

    log.info("Running Semgrep on %s", source_dir)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    proc = subprocess.run(
        ["semgrep", "scan", "--config", "p/ci", "--json", "--output", _RESULTS_FILE, source_dir],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )

    # semgrep exits 0 (clean) or 1 (findings found) — both are success.
    # Any other code means Semgrep itself couldn't run — an operational
    # failure. Previously this called sys.exit(2), which raises SystemExit
    # (a BaseException) and isn't caught by cli.py's `except Exception:`
    # handler — that silently killed the entire `scan` subcommand, skipping
    # every remaining scanner. Raise a plain exception instead so cli.py's
    # existing handler marks semgrep's status as "error" and continues on.
    if proc.returncode not in (0, 1):
        stderr_tail = (proc.stderr or "")[:500]
        raise RuntimeError(
            f"semgrep exited with unexpected code {proc.returncode}: {stderr_tail}"
        )

    if not os.path.exists(_RESULTS_FILE):
        log.info("Semgrep produced no results file — treating as clean.")
        return ScanResult(skipped=True, skip_reason="no results file")

    with open(_RESULTS_FILE, encoding="utf-8") as f:
        data = json.load(f)

    raw_results = data.get("results", [])
    log.info("Semgrep found %d raw result(s)", len(raw_results))

    findings = []
    for r in raw_results:
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append({
            "checkId": r.get("check_id", ""),
            "path": r.get("path", ""),
            "startLine": r.get("start", {}).get("line", 0),
            "endLine": r.get("end", {}).get("line", 0),
            "severity": r.get("severity") or extra.get("severity") or "INFO",
            "message": extra.get("message", ""),
            # try extra.cwe first (older semgrep), fall back to extra.metadata.cwe
            "cwe": extra.get("cwe") or metadata.get("cwe", []),
            "owasp": extra.get("owasp") or metadata.get("owasp", []),
            "projectId": project_id,
            "pipelineRunId": pipeline_run_id,
        })

    return ScanResult(findings=findings)
