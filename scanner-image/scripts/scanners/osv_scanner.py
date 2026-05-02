"""OSV-Scanner -> universal findings."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import subprocess
import sys

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
                    if cvss >= 9:
                        return "CRITICAL"
                    if cvss >= 7:
                        return "HIGH"
                    if cvss >= 4:
                        return "MEDIUM"
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


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    del config
    log.info("Running OSV-Scanner on %s", source_dir)

    candidates = (
        ["osv-scanner", "--format", "json", "--recursive", source_dir],
        ["osv-scanner", "--format", "json", "-r", source_dir],
        ["osv-scanner", "scan", "--format", "json", "--recursive", source_dir],
        ["osv-scanner", "scan", "--format", "json", "-r", source_dir],
    )

    stdout_text = ""
    last_stderr = ""

    for cmd in candidates:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        last_stderr = proc.stderr or ""
        out = (proc.stdout or "").strip()
        log.debug(
            "osv-scanner try %s -> rc=%d len(out)=%d",
            cmd,
            proc.returncode,
            len(out),
        )
        if proc.returncode not in (0, 1):
            continue
        if not out:
            stdout_text = "{}"
            break
        if out.startswith("{"):
            stdout_text = out
            break
    else:
        log.error("OSV-Scanner could not emit JSON stdout. Last stderr: %s", last_stderr[:1200])
        sys.exit(2)

    try:
        data = json.loads(stdout_text)
    except json.JSONDecodeError:
        log.error("OSV-Scanner stdout was not JSON: %s", stdout_text[:500])
        sys.exit(2)

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
