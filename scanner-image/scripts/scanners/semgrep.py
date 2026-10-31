import logging
import os
import subprocess
import tempfile

from .base import ScanResult
from . import tool_output

log = logging.getLogger(__name__)

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

    # A report belongs to one invocation. A fixed /tmp filename can retain a
    # previous run's results, or be overwritten by another concurrent scan.
    with tempfile.TemporaryDirectory(prefix="secureobs-semgrep-") as output_dir:
        output_path = os.path.join(output_dir, "results.json")
        try:
            proc = subprocess.run(
                ["semgrep", "scan", "--config", "p/ci", "--json", "--output", output_path, source_dir],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
                timeout=tool_output.TOOL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"semgrep exceeded the {tool_output.TOOL_TIMEOUT_SECONDS}-second limit"
            ) from exc

        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"semgrep exited with unexpected code {proc.returncode}: "
                f"{tool_output.stderr_tail(proc.stderr)}"
            )

        try:
            data = tool_output.load_json_output(output_path, "semgrep")
        except tool_output.ToolOutputError as exc:
            # A zero process exit is insufficient: the observed release exited
            # zero without a report. Preserve the diagnostic and report failure,
            # so scan-execution status and an opted-in gate cannot call it clean.
            raise tool_output.ToolOutputError(
                f"{exc}. stderr: {tool_output.stderr_tail(proc.stderr) or '(none)'}"
            ) from exc

    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise tool_output.ToolOutputError("semgrep output must contain a results list")
    raw_results = data["results"]
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
