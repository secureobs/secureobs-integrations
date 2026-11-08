"""OSV-Scanner (v1.x) -> universal findings.

Verified against osv-scanner v1.9.2 (the version pinned in the Dockerfile) with
the captured fixtures under ``tests/fixtures/osv-1.9.2``:

* JSON nests advisories per package: ``results[].packages[].vulnerabilities``.
  ``results[].packages[].groups`` lists which advisories are aliases of each
  other (with OSV-Scanner's own ``max_severity`` CVSS score), so one finding is
  emitted per *group*, not per raw advisory record.
* ``severity[].score`` is a CVSS *vector string*, not a number — the numeric
  score comes from ``groups[].max_severity``.
* ``osv-scanner scan <dir>`` exists in v1.9.2 but is NOT recursive; the
  top-level ``--recursive`` form is the one that finds nested lockfiles.
* Exit codes: 0 clean, 1 vulnerabilities found, 128 no package sources found
  (also when the only lockfile fails to parse), 127 general error, and 129
  when api.osv.dev is unreachable.
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import PurePosixPath
from typing import Any

from . import evidence, sca, tool_output
from .base import ScanResult

log = logging.getLogger(__name__)

_OUTPUT_FILE = "/tmp/osv-results.json"
_GENERAL_ERROR_EXIT = 127
_NO_SOURCES_EXIT = 128
# v1.9.2 exits 129 when a call to api.osv.dev fails (observed: proxy 403, no network).
_API_FAILURE_EXIT = 129
_PARSE_FAILURE_RE = re.compile(r"Attempted to scan lockfile but failed: (.+)$")
_SCANNED_RE = re.compile(r"^Scanned (.+) file and found \d+ packages?$")

NO_SOURCES_REASON = "no_supported_manifests"
NO_SOURCES_WARNING = "No supported dependency manifest or lockfile was found."
MAVEN_FALLBACK_WARNING = (
    "Maven resolution failed. Retried using dependencies declared in pom.xml "
    "without resolving the transitive dependency graph."
)


def build_command(source_dir: str, output_path: str = _OUTPUT_FILE, *,
                  resolve_maven: bool = True) -> list[str]:
    command = ["osv-scanner", "--format", "json", "--output", output_path, "--recursive"]
    if not resolve_maven:
        command.append("--experimental-no-resolve")
    return [*command, source_dir]


def run(
    source_dir: str,
    project_id: str,
    pipeline_run_id: str,
    config: dict[str, str] | None = None,
) -> ScanResult:
    del config
    log.info("Running OSV-Scanner on %s", source_dir)

    proc = _invoke(source_dir)
    retry_maven = proc.returncode in (_GENERAL_ERROR_EXIT, _NO_SOURCES_EXIT) and any(
        PurePosixPath(path).name == "pom.xml"
        for path in _unparsed_lockfiles(proc.stderr, source_dir)
    )
    if retry_maven:
        log.warning("osv-scanner: retrying without Maven transitive dependency resolution")
        proc = _invoke(source_dir, resolve_maven=False)

    result = interpret(proc.returncode, proc.stderr, _OUTPUT_FILE,
                       source_dir, project_id, pipeline_run_id)
    if retry_maven:
        if result.skipped:
            raise RuntimeError("osv-scanner found no package sources on the Maven retry")
        result.warnings.insert(0, MAVEN_FALLBACK_WARNING)
    return result


def _invoke(source_dir: str, *, resolve_maven: bool = True) -> subprocess.CompletedProcess[str]:
    tool_output.remove_stale(_OUTPUT_FILE)
    try:
        return subprocess.run(
            build_command(source_dir, _OUTPUT_FILE, resolve_maven=resolve_maven),
            capture_output=True, text=True,
            timeout=tool_output.TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"osv-scanner exceeded the {tool_output.TOOL_TIMEOUT_SECONDS}-second limit") from exc


def interpret(returncode: int, stderr: str, output_path: str, source_dir: str,
              project_id: str, pipeline_run_id: str) -> ScanResult:
    """Turn one osv-scanner invocation into a ScanResult (separated for tests)."""
    unparsed = _unparsed_lockfiles(stderr, source_dir)
    scanned = _scanned_sources(stderr)

    if returncode == _NO_SOURCES_EXIT:
        if unparsed:
            # The only lockfiles present could not be parsed: nothing was
            # analysed, and that is a failure the user must see — not "clean".
            raise RuntimeError(
                "osv-scanner could not parse any lockfile: " + ", ".join(unparsed[:5]))
        log.warning("osv-scanner: %s", NO_SOURCES_WARNING)
        return ScanResult(skipped=True, skip_reason=NO_SOURCES_REASON, not_applicable=True,
                          sources_analyzed=0, warnings=[NO_SOURCES_WARNING])

    if returncode == _API_FAILURE_EXIT:
        raise RuntimeError(
            f"osv-scanner could not query the OSV vulnerability API (exit {returncode}; check "
            f"outbound HTTPS to api.osv.dev): {tool_output.stderr_tail(stderr)}")
    if returncode not in (0, 1):
        if returncode == _GENERAL_ERROR_EXIT and unparsed:
            raise RuntimeError(
                f"osv-scanner could not scan lockfile(s) (exit {returncode}): "
                + ", ".join(unparsed[:5]))
        raise RuntimeError(
            f"osv-scanner exited with unexpected code {returncode}: "
            f"{tool_output.stderr_tail(stderr, limit=200)}")

    data = tool_output.load_json_output(output_path, "osv-scanner")
    result = parse_report(data, source_dir, project_id, pipeline_run_id)
    if scanned:
        result.sources_analyzed = max(result.sources_analyzed or 0, len(scanned))
    if unparsed:
        warning = (f"{len(unparsed)} lockfile(s) could not be parsed and were skipped: "
                   + ", ".join(unparsed[:5]))
        log.warning("osv-scanner: %s", warning)
        result.warnings.append(warning)
    return result


def _unparsed_lockfiles(stderr: str, source_dir: str) -> list[str]:
    out = []
    for line in stderr.splitlines():
        match = _PARSE_FAILURE_RE.search(line.strip())
        if match:
            rel = evidence.relative_path(match.group(1), source_dir)
            if rel and rel not in out:
                out.append(rel)
    return out


def _scanned_sources(stderr: str) -> list[str]:
    return [m.group(1) for m in (_SCANNED_RE.match(ln.strip()) for ln in stderr.splitlines()) if m]


def parse_report(data: Any, source_dir: str, project_id: str, pipeline_run_id: str) -> ScanResult:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise tool_output.ToolOutputError("osv-scanner output has no 'results' list")

    findings: list[dict] = []
    for block in data["results"]:
        if not isinstance(block, dict):
            continue
        source = block.get("source") or {}
        manifest = evidence.relative_path(source.get("path"), source_dir)
        for pkg_entry in block.get("packages") or []:
            if isinstance(pkg_entry, dict):
                findings.extend(_package_findings(pkg_entry, manifest, project_id, pipeline_run_id))

    log.info("OSV-Scanner produced %d finding row(s)", len(findings))
    return ScanResult(findings=findings, sources_analyzed=len(data["results"]))


def _groups(pkg_entry: dict) -> list[dict]:
    """Alias groups for a package; one synthetic group per advisory if absent."""
    vulns = [v for v in pkg_entry.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("id")]
    groups = [g for g in pkg_entry.get("groups") or [] if isinstance(g, dict) and g.get("ids")]
    covered = {i for g in groups for i in g.get("ids") or []}
    for v in vulns:
        if v["id"] not in covered:
            groups.append({"ids": [v["id"]], "aliases": v.get("aliases") or []})
    return groups


def _fixed_versions(vulns: list[dict], ecosystem: str | None, name: str) -> tuple[list[str], bool]:
    fixed: list[str] = []
    has_ranges = False
    for v in vulns:
        for affected in v.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            apkg = affected.get("package") or {}
            if apkg.get("name") and sca.normalize_name(ecosystem, str(apkg.get("name"))) != \
                    sca.normalize_name(ecosystem, name):
                continue
            for rng in affected.get("ranges") or []:
                has_ranges = True
                for event in (rng or {}).get("events") or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        fixed.append(str(event["fixed"]))
    return fixed, has_ranges


def _package_findings(pkg_entry: dict, manifest: str | None,
                      project_id: str, pipeline_run_id: str) -> list[dict]:
    pkg = pkg_entry.get("package") or {}
    name = str(pkg.get("name") or "")
    version = str(pkg.get("version") or "")
    ecosystem = sca.normalize_ecosystem(pkg.get("ecosystem"))
    scope = sca.scope_from_groups(pkg_entry.get("dependency_groups"))
    by_id = {v["id"]: v for v in pkg_entry.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("id")}

    out: list[dict] = []
    for group in _groups(pkg_entry):
        ids = [i for i in (evidence.advisory_id(x) for x in group.get("ids") or []) if i]
        vulns = [by_id[i] for i in group.get("ids") or [] if i in by_id]
        if not ids:
            continue
        aliases = {a for a in (evidence.advisory_id(x) for x in group.get("aliases") or []) if a}
        for v in vulns:
            aliases.update(a for a in (evidence.advisory_id(x) for x in v.get("aliases") or []) if a)
        aliases.update(ids)

        key = sca.vulnerability_key(ids[0], sorted(aliases)) or ids[0]
        primary = vulns[0] if vulns else {}
        db_specific = primary.get("database_specific") or {}

        score = None
        try:
            score = float(group.get("max_severity")) if group.get("max_severity") not in (None, "") else None
        except (TypeError, ValueError):
            score = None
        severity = sca.severity_from_cvss(score)
        severity_source = "osv-max-cvss" if severity else None
        if severity is None:
            severity = sca.normalize_severity(db_specific.get("severity"))
            severity_source = "advisory" if severity else None
        vector = next((s.get("score") for s in primary.get("severity") or []
                       if isinstance(s, dict) and str(s.get("type", "")).startswith("CVSS")), None)

        fixed_raw, has_ranges = _fixed_versions(vulns, ecosystem, name)
        fixed = sca.upgrade_targets(version, fixed_raw)
        fix_status = "fixed" if fixed else ("no_fix" if has_ranges else "unknown")

        references = [evidence.advisory_url(r.get("url")) for r in primary.get("references") or []
                      if isinstance(r, dict) and r.get("type") == "ADVISORY"]

        record = sca.ScaRecord(
            tool="osv-scanner",
            ecosystem=ecosystem,
            package_name=name,
            installed_version=version,
            manifest_path=manifest,
            vulnerability_id=key,
            aliases=sorted(aliases),
            title=primary.get("summary"),
            description=primary.get("details") or primary.get("summary"),
            severity=severity,
            severity_source=severity_source,
            cvss_score=score if severity_source == "osv-max-cvss" else None,
            cvss_vector=vector,
            fixed_versions=fixed,
            fix_status=fix_status,
            purl=None,  # OSV v1 reports no versioned PURL; never synthesize one.
            relationship=None,  # OSV v1 does not report direct vs transitive.
            scope=scope,
            cwe_ids=evidence.cwe_ids(db_specific.get("cwe_ids")),
            references=[r for r in references if r],
            published_at=primary.get("published"),
        )
        eco_key, name_key, version_key, manifest_key, vuln_key = record.identity()
        out.append({
            "scanner": "osv-scanner",
            "ruleId": key,
            "filePath": manifest,
            "codeSnippet": None,
            "severity": severity or "UNKNOWN",
            "description": record.description_text(),
            "cweIds": record.cwe_ids or None,
            "owaspCategories": None,
            "startLine": None,
            "endLine": None,
            "projectId": project_id,
            "pipelineRunId": pipeline_run_id,
            "fingerprint": sca.fingerprint("osv-scanner", "vuln", manifest_key, eco_key,
                                           name_key, version_key, vuln_key),
            "rawPayload": record.evidence_json(),
        })
    return out
