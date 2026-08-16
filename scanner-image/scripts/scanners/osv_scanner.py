"""OSV-Scanner -> universal findings."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import subprocess

from .base import ScanResult

log = logging.getLogger(__name__)

_OUTPUT_FILE = "/tmp/osv-results.json"


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


def _try_invoke(source_dir: str) -> tuple[bool, str]:
    """
    Run OSV-Scanner, writing JSON output to _OUTPUT_FILE.
    Returns (success, stderr).

    Exit codes per OSV-Scanner contract:
      0 = scan completed, no vulnerabilities
      1 = scan completed, vulnerabilities found
    Any other exit code is a real failure — do not mask it.

    Lockfile parse warnings (e.g. 'Attempted to scan lockfile but failed')
    come on stderr. They are logged at WARNING but do not abort the scan;
    findings from other lockfiles in the same run are still valid.
    """
    candidates = [
        # v2.x syntax (try first — newer installs)
        ["osv-scanner", "scan", "--format", "json",
         "--output", _OUTPUT_FILE, source_dir],
        # v1.x syntax
        ["osv-scanner", "--format", "json",
         "--output", _OUTPUT_FILE, "--recursive", source_dir],
    ]

    for cmd in candidates:
        # Clean up any leftover output file from a previous attempt.
        try:
            os.remove(_OUTPUT_FILE)
        except FileNotFoundError:
            pass

        proc = subprocess.run(cmd, capture_output=True, text=True)
        stderr = (proc.stderr or "").strip()

        log.debug("osv-scanner %s -> rc=%d", " ".join(cmd[1:3]), proc.returncode)

        # Surface lockfile parse warnings without aborting.
        if stderr:
            for line in stderr.splitlines():
                if "failed" in line.lower() or "error" in line.lower() or "warn" in line.lower():
                    log.warning("osv-scanner: %s", line)

        if proc.returncode in (0, 1):
            return True, stderr

        # Non 0/1 exit — this command variant didn't work, try the next.
        log.debug("osv-scanner exited %d; trying next command variant", proc.returncode)

    return False, stderr  # type: ignore[possibly-undefined]


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    del config
    log.info("Running OSV-Scanner on %s", source_dir)

    success, stderr = _try_invoke(source_dir)

    if not success:
        # Both CLI syntax variants failed with an exit code outside {0, 1} —
        # osv-scanner itself couldn't run, an operational failure (as the
        # docstring above already says: "do not mask it"). Raise so cli.py's
        # exception handler marks this scanner's status as "error" (not
        # "skipped") and continues on to the remaining scanners.
        raise RuntimeError(f"osv-scanner invocation failed: {stderr[-500:]}")

    if not os.path.isfile(_OUTPUT_FILE):
        log.info("OSV-Scanner produced no output file — no supported lockfiles found.")
        return ScanResult(findings=[])

    try:
        with open(_OUTPUT_FILE) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        # osv-scanner ran but produced untrustworthy output — also an
        # operational failure, not a legitimate skip.
        raise RuntimeError(f"osv-scanner output file could not be parsed: {exc}") from exc

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
