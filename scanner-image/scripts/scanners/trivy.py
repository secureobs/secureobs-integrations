"""Trivy filesystem scan -> universal findings."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import subprocess

from .base import ScanResult

log = logging.getLogger(__name__)

_OUT = "/tmp/secureobs-trivy.json"


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
    log.info("Running Trivy fs on %s", source_dir)

    proc = subprocess.run(
        [
            "trivy",
            "fs",
            "--scanners",
            "vuln,misconfig,secret",
            "--format",
            "json",
            "--output",
            _OUT,
            source_dir,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):
        # Exit codes outside {0, 1} mean Trivy itself couldn't run — an
        # operational failure. Previously this called sys.exit(2), which
        # raises SystemExit (a BaseException) and isn't caught by cli.py's
        # `except Exception:` handler — that silently killed the entire
        # `scan` subcommand, skipping every remaining scanner. Raise a plain
        # exception instead so cli.py's existing handler marks trivy's
        # status as "error" and continues on to the remaining scanners.
        stderr_tail = (proc.stderr or "")[:800]
        raise RuntimeError(
            f"trivy exited with unexpected code {proc.returncode}: {stderr_tail}"
        )

    if not os.path.exists(_OUT):
        return ScanResult(skipped=True, skip_reason="no trivy output file")

    with open(_OUT, encoding="utf-8") as f:
        data = json.load(f)

    findings: list[dict] = []
    results = data.get("Results") or []
    for block in results:
        target = block.get("Target") or ""

        for v in block.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or v.get("ID") or "UNKNOWN"
            sev = (v.get("Severity") or "LOW").upper()
            pkg = v.get("PkgName") or ""
            installed = v.get("InstalledVersion") or ""
            # Trivy's `Results[].Target` for Java/Maven is often `pom.xml` for *every*
            # dependency finding — misleading for dashboard "file location". Prefer
            # package-level attribution when we're under a pom/gradle lock target.
            pkg_path_raw = (
                v.get("PkgPath")
                or v.get("FilePath")
                or ""
            )
            installed_files = v.get("InstalledFiles")
            if not pkg_path_raw and isinstance(installed_files, list) and installed_files:
                pkg_path_raw = str(installed_files[0])

            if pkg_path_raw:
                display_path = str(pkg_path_raw)
            elif pkg and installed:
                tgt = target or "lockfile"
                display_path = f"{pkg}@{installed} ({tgt})"
            elif pkg:
                display_path = f"{pkg} ({target})"
            else:
                display_path = target or "/"

            title = v.get("Title") or vid
            desc = "\n".join(
                filter(
                    None,
                    [
                        title,
                        f"Package: {pkg} @ {installed}" if pkg else "",
                        v.get("PrimaryURL") or v.get("DataSource") or "",
                    ],
                )
            )

            fingerprint = _fp("trivy", "vuln", vid, display_path, pkg, installed)

            findings.append(
                {
                    "scanner": "trivy",
                    "ruleId": vid,
                    "filePath": display_path,
                    "codeSnippet": None,
                    "severity": sev,
                    "description": desc,
                    "cweIds": None,
                    "owaspCategories": None,
                    "startLine": None,
                    "endLine": None,
                    "projectId": project_id,
                    "pipelineRunId": pipeline_run_id,
                    "fingerprint": fingerprint,
                    "rawPayload": json.dumps(v, separators=(",", ":"))[:80_000],
                }
            )

        for m in block.get("Misconfigurations") or []:
            mid = m.get("ID") or m.get("AvdID") or m.get("Type") or "MISCONF"
            sev = (m.get("Severity") or "MEDIUM").upper()
            cm = m.get("CauseMetadata") or {}
            start = cm.get("Start")
            endline = cm.get("End")

            desc_parts = filter(
                None,
                [
                    m.get("Title"),
                    m.get("Message") or m.get("Description"),
                ],
            )

            fingerprint = _fp("trivy", "misconf", mid, target, str(start))

            findings.append(
                {
                    "scanner": "trivy",
                    "ruleId": mid,
                    "filePath": target,
                    "codeSnippet": None,
                    "severity": sev,
                    "description": "\n".join(desc_parts) or mid,
                    "cweIds": None,
                    "owaspCategories": None,
                    "startLine": int(start) if start is not None else None,
                    "endLine": int(endline) if endline is not None else None,
                    "projectId": project_id,
                    "pipelineRunId": pipeline_run_id,
                    "fingerprint": fingerprint,
                    "rawPayload": json.dumps(m, separators=(",", ":"))[:80_000],
                }
            )

        for srec in block.get("Secrets") or []:
            rid = srec.get("RuleID") or "SECRET"
            sev = (srec.get("Severity") or "HIGH").upper()
            mt = (srec.get("Match") or "")[:4096]

            fingerprint = _fp("trivy", "secret", rid, target, str(srec.get("StartLine")))

            findings.append(
                {
                    "scanner": "trivy",
                    "ruleId": rid,
                    "filePath": target,
                    "codeSnippet": mt or None,
                    "severity": sev,
                    "description": srec.get("Title") or rid,
                    "cweIds": None,
                    "owaspCategories": None,
                    "startLine": srec.get("StartLine"),
                    "endLine": srec.get("EndLine"),
                    "projectId": project_id,
                    "pipelineRunId": pipeline_run_id,
                    "fingerprint": fingerprint,
                    "rawPayload": json.dumps(srec, separators=(",", ":"))[:80_000],
                }
            )

    log.info("Trivy produced %d finding row(s)", len(findings))
    return ScanResult(findings=findings)
