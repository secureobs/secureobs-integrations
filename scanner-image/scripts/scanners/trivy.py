"""Trivy filesystem scan -> universal findings.

One Trivy invocation covers three categories that the dashboard keeps apart:

* ``Vulnerabilities`` in dependency manifests/lockfiles → SCA findings with
  structured package evidence (kind ``sca``).
* ``Misconfigurations`` → IaC findings (kind ``iac``), unchanged.
* ``Secrets`` → secret findings (kind ``secret``), unchanged. Trivy censors the
  matched value itself; the evidence envelope never carries the match or the
  surrounding code lines.

Verified against Trivy 0.70.0 (the version pinned in the Dockerfile) using the
captured fixtures under ``tests/fixtures/trivy-0.70.0``.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Any

from . import evidence, sca, tool_output
from .base import ScanResult

log = logging.getLogger(__name__)

_OUT = "/tmp/secureobs-trivy.json"
_SCA_CLASSES = {"lang-pkgs", "os-pkgs"}
_NO_FIX_STATUSES = {"affected", "will_not_fix", "fix_deferred", "end_of_life"}
NO_SOURCES_WARNING = (
    "No supported dependency manifest or lockfile was found, so Trivy's dependency "
    "(SCA) scan analysed nothing. Secret and IaC checks still ran."
)


def _fp(*parts: str) -> str:
    return sca.fingerprint(*parts)


def build_command(source_dir: str, output_path: str = _OUT) -> list[str]:
    return [
        "trivy", "fs",
        "--scanners", "vuln,misconfig,secret",
        "--format", "json",
        "--output", output_path,
        source_dir,
    ]


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    del config
    log.info("Running Trivy fs on %s", source_dir)
    tool_output.remove_stale(_OUT)

    try:
        proc = subprocess.run(
            build_command(source_dir), capture_output=True, text=True,
            timeout=tool_output.TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"trivy exceeded the {tool_output.TOOL_TIMEOUT_SECONDS}-second limit") from exc

    if proc.returncode not in (0, 1):
        # Exit codes outside {0, 1} mean Trivy itself couldn't run — an
        # operational failure. Raise (not sys.exit) so cli.py records this
        # scanner as failed and continues with the remaining scanners.
        raise RuntimeError(
            f"trivy exited with unexpected code {proc.returncode}: "
            f"{tool_output.stderr_tail(proc.stderr)}")

    data = tool_output.load_json_output(_OUT, "trivy")
    return parse_report(data, source_dir, project_id, pipeline_run_id)


def parse_report(data: Any, source_dir: str, project_id: str, pipeline_run_id: str) -> ScanResult:
    if not isinstance(data, dict):
        raise tool_output.ToolOutputError("trivy output is not a JSON object")
    results = data.get("Results") or []
    if not isinstance(results, list):
        raise tool_output.ToolOutputError("trivy output 'Results' is not a list")

    findings: list[dict] = []
    sources = 0
    for block in results:
        if not isinstance(block, dict):
            continue
        target = str(block.get("Target") or "")
        if block.get("Class") in _SCA_CLASSES:
            sources += 1
        packages = _index_packages(block.get("Packages"))

        for v in block.get("Vulnerabilities") or []:
            if isinstance(v, dict):
                findings.append(_vulnerability(v, block, target, packages, source_dir,
                                               project_id, pipeline_run_id))
        for m in block.get("Misconfigurations") or []:
            if isinstance(m, dict):
                findings.append(_misconfiguration(m, target, project_id, pipeline_run_id))
        for s in block.get("Secrets") or []:
            if isinstance(s, dict):
                findings.append(_secret(s, target, project_id, pipeline_run_id))

    warnings = [] if sources else [NO_SOURCES_WARNING]
    if not sources:
        log.warning("trivy: %s", NO_SOURCES_WARNING)
    log.info("Trivy produced %d finding row(s) from %d dependency source(s)", len(findings), sources)
    return ScanResult(findings=findings, sources_analyzed=sources, warnings=warnings)


def _index_packages(packages: Any) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for pkg in packages or []:
        if not isinstance(pkg, dict):
            continue
        uid = (pkg.get("Identifier") or {}).get("UID")
        if uid:
            index[f"uid:{uid}"] = pkg
        if pkg.get("ID"):
            index[f"id:{pkg['ID']}"] = pkg
    return index


def _relationship(pkg: dict | None) -> str | None:
    rel = str((pkg or {}).get("Relationship") or "").lower()
    if rel == "direct":
        return "direct"
    if rel == "indirect":
        return "transitive"
    return None  # root / workspace / unknown / not reported (e.g. pip, gradle)


def _cvss(v: dict) -> tuple[float | None, str | None]:
    cvss = v.get("CVSS") if isinstance(v.get("CVSS"), dict) else {}
    source = v.get("SeveritySource")
    entry = cvss.get(source) or cvss.get("nvd") or cvss.get("ghsa") or next(iter(cvss.values()), {})
    if not isinstance(entry, dict):
        return None, None
    score = entry.get("V3Score") or entry.get("V40Score")
    vector = entry.get("V3Vector") or entry.get("V40Vector")
    try:
        score_value = float(score) if score is not None else None
    except (TypeError, ValueError):
        score_value = None
    if score_value is not None and not 0 < score_value <= 10:
        score_value = None
    return score_value, vector


def _vulnerability(v: dict, block: dict, target: str, packages: dict[str, dict],
                   source_dir: str, project_id: str, pipeline_run_id: str) -> dict:
    vid = v.get("VulnerabilityID") or v.get("ID") or "UNKNOWN"
    raw_severity = (v.get("Severity") or "UNKNOWN").upper()
    pkg_name = v.get("PkgName") or ""
    installed = v.get("InstalledVersion") or ""

    # ── Legacy identity: kept byte-for-byte so findings ingested by earlier
    # images (and their suppressions) keep matching on re-scan. ──
    pkg_path_raw = v.get("PkgPath") or v.get("FilePath") or ""
    installed_files = v.get("InstalledFiles")
    if not pkg_path_raw and isinstance(installed_files, list) and installed_files:
        pkg_path_raw = str(installed_files[0])
    if pkg_path_raw:
        display_path = str(pkg_path_raw)
    elif pkg_name and installed:
        display_path = f"{pkg_name}@{installed} ({target or 'lockfile'})"
    elif pkg_name:
        display_path = f"{pkg_name} ({target})"
    else:
        display_path = target or "/"
    legacy_fingerprint = _fp("trivy", "vuln", vid, display_path, pkg_name, installed)

    identifier = v.get("PkgIdentifier") or {}
    pkg = packages.get(f"uid:{identifier.get('UID')}") or packages.get(f"id:{v.get('PkgID')}")
    manifest = evidence.relative_path(pkg_path_raw or target, source_dir)
    ecosystem = sca.ecosystem_from_purl(identifier.get("PURL")) or sca.ecosystem_from_trivy_type(block.get("Type"))

    fixed = sca.upgrade_targets(installed, [p.strip() for p in str(v.get("FixedVersion") or "").split(",")])
    status = str(v.get("Status") or "").lower()
    fix_status = "fixed" if fixed else ("no_fix" if status in _NO_FIX_STATUSES else "unknown")
    score, vector = _cvss(v)
    references = [evidence.advisory_url(v.get("PrimaryURL"))] + [
        evidence.advisory_url(r) for r in (v.get("References") or [])[:40]]

    record = sca.ScaRecord(
        tool="trivy",
        ecosystem=ecosystem,
        package_name=pkg_name,
        installed_version=installed,
        manifest_path=manifest,
        vulnerability_id=evidence.advisory_id(vid) or "UNKNOWN",
        aliases=[a for a in (evidence.advisory_id(x) for x in v.get("VendorIDs") or []) if a],
        title=v.get("Title"),
        description=v.get("Description"),
        severity=sca.normalize_severity(raw_severity),
        severity_source=v.get("SeveritySource"),
        cvss_score=score,
        cvss_vector=vector,
        fixed_versions=fixed,
        fix_status=fix_status,
        purl=identifier.get("PURL"),
        relationship=_relationship(pkg),
        scope="development" if (pkg or {}).get("Dev") else None,
        cwe_ids=evidence.cwe_ids(v.get("CweIDs")),
        references=[r for r in references if r],
        published_at=v.get("PublishedDate"),
    )

    locations = (pkg or {}).get("Locations") or []
    first_location = locations[0] if locations and isinstance(locations[0], dict) else {}
    start = first_location.get("StartLine")
    end = first_location.get("EndLine")

    return {
        "scanner": "trivy",
        "ruleId": (evidence.clean_line(vid, evidence.MAX_RULE_ID_CHARS) or "UNKNOWN"),
        "filePath": manifest or evidence.clean_line(target, evidence.MAX_PATH_CHARS),
        "codeSnippet": None,
        "severity": raw_severity,
        "description": record.description_text(),
        "cweIds": record.cwe_ids or None,
        "owaspCategories": None,
        "startLine": start if isinstance(start, int) and start > 0 else None,
        "endLine": end if isinstance(end, int) and end > 0 else None,
        "projectId": project_id,
        "pipelineRunId": pipeline_run_id,
        "fingerprint": legacy_fingerprint,
        "rawPayload": record.evidence_json(),
    }


def _misconfiguration(m: dict, target: str, project_id: str, pipeline_run_id: str) -> dict:
    mid = m.get("ID") or m.get("AvdID") or m.get("Type") or "MISCONF"
    sev = (m.get("Severity") or "MEDIUM").upper()
    cm = m.get("CauseMetadata") or {}
    start = cm.get("Start") if cm.get("Start") is not None else cm.get("StartLine")
    endline = cm.get("End") if cm.get("End") is not None else cm.get("EndLine")
    # Fingerprint keeps the pre-existing inputs (CauseMetadata.Start) so
    # historical IaC findings keep matching.
    fingerprint = _fp("trivy", "misconf", mid, target, str(cm.get("Start")))
    desc = "\n".join(filter(None, [m.get("Title"), m.get("Message") or m.get("Description")])) or mid

    payload = evidence.envelope("iac", {
        "ruleId": evidence.clean_line(mid, 128),
        "title": evidence.clean_line(m.get("Title"), 300),
        "resolution": evidence.clean_text(m.get("Resolution"), 600),
        "provider": evidence.clean_line(cm.get("Provider"), 64),
        "service": evidence.clean_line(cm.get("Service"), 64),
        "advisoryUrl": evidence.advisory_url(m.get("PrimaryURL")),
        "detectedBy": ["trivy"],
    })
    return {
        "scanner": "trivy",
        "ruleId": mid,
        "filePath": target,
        "codeSnippet": None,
        "severity": sev,
        "description": evidence.clean_text(desc, evidence.MAX_DESCRIPTION_CHARS) or mid,
        "cweIds": None,
        "owaspCategories": None,
        "startLine": int(start) if isinstance(start, int) else None,
        "endLine": int(endline) if isinstance(endline, int) else None,
        "projectId": project_id,
        "pipelineRunId": pipeline_run_id,
        "fingerprint": fingerprint,
        "rawPayload": payload,
    }


def _secret(s: dict, target: str, project_id: str, pipeline_run_id: str) -> dict:
    rid = s.get("RuleID") or "SECRET"
    sev = (s.get("Severity") or "HIGH").upper()
    # Trivy masks the matched value (asterisks) in Match; the snippet keeps the
    # pre-existing behaviour. The evidence envelope never includes it.
    match = (s.get("Match") or "")[:4096]
    fingerprint = _fp("trivy", "secret", rid, target, str(s.get("StartLine")))
    payload = evidence.envelope("secret", {
        "ruleId": evidence.clean_line(rid, 128),
        "category": evidence.clean_line(s.get("Category"), 64),
        "title": evidence.clean_line(s.get("Title"), 200),
        "detectedBy": ["trivy"],
    })
    return {
        "scanner": "trivy",
        "ruleId": rid,
        "filePath": target,
        "codeSnippet": match or None,
        "severity": sev,
        "description": s.get("Title") or rid,
        "cweIds": None,
        "owaspCategories": None,
        "startLine": s.get("StartLine"),
        "endLine": s.get("EndLine"),
        "projectId": project_id,
        "pipelineRunId": pipeline_run_id,
        "fingerprint": fingerprint,
        "rawPayload": payload,
    }
