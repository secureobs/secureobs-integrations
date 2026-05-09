"""OSV-Scanner -> universal findings."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import subprocess

from .base import ScanResult

log = logging.getLogger(__name__)


def _fp(*parts: str) -> str:
    s = "|".join(str(p or "") for p in parts).encode()
    return base64.b64encode(hashlib.sha256(s).digest()).decode().strip()


def _severity_from_vuln(vuln: dict) -> str:
    sv = vuln.get("severity")
    if isinstance(sv, list) and sv:
        first = sv[0]
        score = str(first.get("score") or "")
        if "/" in score:
            try:
                rhs = float(score.split("/")[-1])
                lhs = float(score.split("/")[0])
                if rhs > 0:
                    cvss = lhs / rhs * 10
                    if cvss >= 9:   return "CRITICAL"
                    if cvss >= 7:   return "HIGH"
                    if cvss >= 4:   return "MEDIUM"
                    return "LOW"
            except (ValueError, ZeroDivisionError):
                pass
        txt = str(score).upper()
        for tag in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if tag in txt:
                return tag
        if "7." in score:
            return "HIGH"
    return "MEDIUM"


def _try_commands(source_dir: str) -> tuple[str | None, str]:
    """
    Try every known OSV-Scanner command format.
    Returns (stdout_json_or_none, last_stderr).

    Priority rule: if stdout contains valid JSON we use it immediately,
    regardless of exit code — partial results (some lockfiles failed to
    parse) are still valuable findings.
    """
    candidates = [
        # v2.x syntax
        ["osv-scanner", "scan", "--format", "json", source_dir],
        ["osv-scanner", "scan", "--format", "json", "--recursive", source_dir],
        # v1.x syntax
        ["osv-scanner", "--format", "json", "--recursive", source_dir],
        ["osv-scanner", "--format", "json", "-r", source_dir],
    ]

    last_stderr = ""
    had_normal_exit = False

    for cmd in candidates:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        last_stderr = proc.stderr or ""
        out = (proc.stdout or "").strip()

        log.debug("osv-scanner %s -> rc=%d stdout_len=%d", cmd[1], proc.returncode, len(out))

        # If stdout looks like JSON, use it — even a partial scan is useful.
        if out.startswith("{"):
            return out, last_stderr

        # Normal exit with no output means no supported lockfiles found.
        if proc.returncode in (0, 1, 2):
            had_normal_exit = True

    # No command produced JSON. Return empty string so caller can decide.
    return (None if not had_normal_exit else "{}"), last_stderr


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    del config
    log.info("Running OSV-Scanner on %s", source_dir)

    stdout_json, last_stderr = _try_commands(source_dir)

    if stdout_json is None:
        # Every command exited abnormally and produced no JSON.
        # Log but don't crash — degrade gracefully.
        log.warning(
            "OSV-Scanner produced no usable output on any command format — "
            "returning zero findings. Last stderr: %s",
            last_stderr[:1200],
        )
        return ScanResult(findings=[])

    if not stdout_json or stdout_json == "{}":
        log.info("OSV-Scanner found no lockfiles to scan.")
        return ScanResult(findings=[])

    try:
        data = json.loads(stdout_json)
    except json.JSONDecodeError:
        log.warning("OSV-Scanner stdout was not valid JSON — returning zero findings: %s", stdout_json[:500])
        return ScanResult(findings=[])

    findings: list[dict] = []
    for block in data.get("results") or []:
        src = block.get("source") or {}
        path = src.get("path") or ""
        for vuln in block.get("vulnerabilities") or []:
            vid = vuln.get("id") or "OSV"
            sev = _severity_from_vuln(vuln)
            summary = vuln.get("details") or vuln.get("summary") or vid

            fingerprint = _fp("osv-scanner", vid, path, summary[:200])

            pkg_bits = []
            for pkg_entry in block.get("packages") or []:
                pkg = pkg_entry.get("package") or {}
                if pkg.get("name"):
                    pkg_bits.append(f"{pkg.get('name')}@{pkg.get('version', '')}")

            desc = summary
            if pkg_bits:
                desc = f"{summary}\nAffected: {', '.join(pkg_bits)}"

            findings.append(
                {
                    "scanner": "osv-scanner",
                    "ruleId": vid,
                    "filePath": path or None,
                    "codeSnippet": None,
                    "severity": sev,
                    "description": desc[:16_000],
                    "cweIds": None,
                    "owaspCategories": None,
                    "startLine": None,
                    "endLine": None,
                    "projectId": project_id,
                    "pipelineRunId": pipeline_run_id,
                    "fingerprint": fingerprint,
                    "rawPayload": json.dumps(vuln, separators=(",", ":"))[:80_000],
                }
            )

    log.info("OSV-Scanner produced %d finding row(s)", len(findings))
    return ScanResult(findings=findings)
