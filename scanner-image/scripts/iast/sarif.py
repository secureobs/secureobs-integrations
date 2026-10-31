"""Validate and normalize an IAST report exported as SARIF 2.1.0.

What makes a SARIF result an IAST finding here — and not static analysis that
was merely uploaded with ``import-iast``:

1. The producing tool (``runs[].tool.driver.name``) is not a known static,
   dependency, secret, IaC or DAST scanner, and matches the declared provider.
2. The result carries runtime evidence: the HTTP request the instrumented app
   was serving when the agent observed the issue (SARIF ``result.webRequest``,
   §3.27.31, or a ``run.webRequests`` entry it references). Results without it
   are skipped and counted; a report where *no* result has it is rejected.

Everything kept is sanitized: routes become path-only templates, free text is
redacted, request/response headers, bodies, parameters and cookies are never
read at all, and every string is length-capped.
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from scanners import evidence, sca

from . import providers, redact

DEFAULT_MAX_REPORT_BYTES = 10 * 1024 * 1024
HARD_MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_RUNS = 20
MAX_RESULTS = 10_000
MAX_FLOW_STEPS = 20
SCANNER_KEY = "iast"

_RULE_ID_SAFE_RE = re.compile(r"[^A-Za-z0-9._:/\-]+")
_VENDOR_ID_RE = re.compile(r"^[A-Za-z0-9._:/=+\-]{1,128}$")
_SESSION_RE = re.compile(r"[^A-Za-z0-9._:/@\-]+")
_CWE_TAG_RE = re.compile(r"(?:external/cwe/cwe-|\bCWE[-_ ]?)(\d{1,6})\b", re.IGNORECASE)
_SKIPPED_KINDS = {"pass", "notapplicable", "informational"}
_LEVEL_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}


class ReportMissing(Exception):
    """The report file does not exist or cannot be read (exit code 5)."""


class ReportRejected(Exception):
    """The report is not a valid, genuine IAST report (exit code 6)."""


@dataclass
class ImportedReport:
    provider: providers.Provider
    tool_name: str
    tool_version: str | None
    total_results: int = 0
    findings: list[dict] = field(default_factory=list)
    skipped_no_runtime_evidence: int = 0
    skipped_not_findings: int = 0
    test_session: str | None = None
    warnings: list[str] = field(default_factory=list)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _check_json_depth(text: str) -> None:
    # Bound nesting before allocating the decoded object graph. Python 3.15's
    # JSON decoder accepts depths that previously raised RecursionError, so
    # interpreter recursion limits are not a reliable input limit.
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ReportRejected(f"report JSON nesting exceeds the {MAX_JSON_DEPTH}-level limit")
        elif char in "]}":
            depth -= 1
    # Full syntax/type validation remains the JSON decoder's responsibility.


def load_report(path: str, max_bytes: int = DEFAULT_MAX_REPORT_BYTES) -> Any:
    """Read the report file with size and type checks before parsing it."""
    if not path:
        raise ReportMissing("no report path was given")
    try:
        st = os.stat(path)
    except FileNotFoundError as exc:
        raise ReportMissing(f"report file not found: {path}") from exc
    except OSError as exc:
        raise ReportMissing(f"report file cannot be accessed: {path} ({exc.strerror})") from exc
    if not stat.S_ISREG(st.st_mode):
        # Directories, FIFOs and devices are refused before any read so a
        # mis-mounted path (or /dev/zero) cannot hang or exhaust the job.
        raise ReportRejected(f"report path is not a regular file: {path}")
    if st.st_size == 0:
        raise ReportRejected("report file is empty")
    if st.st_size > max_bytes:
        raise ReportRejected(
            f"report is {st.st_size} bytes, above the {max_bytes}-byte limit "
            "(raise --max-report-bytes up to 50 MiB if this is expected)")
    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError as exc:
        raise ReportMissing(f"report file cannot be read: {path} ({exc.strerror})") from exc
    if len(raw) > max_bytes:
        raise ReportRejected("report grew past the size limit while being read")
    try:
        text = raw.decode("utf-8-sig")
        _check_json_depth(text)
        return json.loads(text, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ReportRejected(f"report is not valid JSON ({type(exc).__name__})") from exc


def _text(obj: Any) -> str | None:
    """SARIF message/multiformat text. Markdown is ignored — it may carry HTML."""
    if isinstance(obj, dict) and isinstance(obj.get("text"), str):
        return obj["text"]
    return None


def _severity(result: dict, rule: dict) -> tuple[str | None, str | None, float | None]:
    for props in (result.get("properties"), rule.get("properties")):
        if isinstance(props, dict) and props.get("security-severity") not in (None, ""):
            sev = sca.severity_from_cvss(props.get("security-severity"))
            if sev:
                return sev, "security-severity", float(props["security-severity"])
    level = result.get("level")
    if level is None:
        default_config = rule.get("defaultConfiguration")
        level = default_config.get("level") if isinstance(default_config, dict) else None
    if level is None:
        return "MEDIUM", "sarif-default-level", None  # SARIF §3.27.10: default level is "warning"
    sev = _LEVEL_SEVERITY.get(str(level).lower())
    return sev, ("sarif-level" if sev else None), None


def _cwes(result: dict, rule: dict) -> list[str]:
    found: list[str] = []
    props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    for tag in props.get("tags") or []:
        for m in _CWE_TAG_RE.finditer(str(tag)):
            found.append(f"CWE-{int(m.group(1))}")
    refs = list(result.get("taxa") or []) + [
        r.get("target") for r in rule.get("relationships") or [] if isinstance(r, dict)]
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        component = ref.get("toolComponent") if isinstance(ref.get("toolComponent"), dict) else {}
        if str(component.get("name", "")).upper() == "CWE" and str(ref.get("id", "")).isdigit():
            found.append(f"CWE-{int(ref['id'])}")
    return evidence.cwe_ids(found)


def _code_path(uri: Any) -> str | None:
    text = evidence.clean_line(uri, 1024)
    if not text:
        return None
    if text.lower().startswith("file://"):
        text = text[7:]
    elif re.match(r"^[a-z][a-z0-9+.-]*:", text, re.IGNORECASE) and not re.match(r"^[a-z]:[\\/]", text, re.IGNORECASE):
        return None  # http:, data:, … are not source files
    text = text.replace("\\", "/")
    text = re.sub(r"^[A-Za-z]:/", "", text).lstrip("/")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)[:512]


def _location(loc: Any) -> tuple[str | None, int | None, int | None, str | None]:
    if not isinstance(loc, dict):
        return None, None, None, None
    physical = loc.get("physicalLocation") if isinstance(loc.get("physicalLocation"), dict) else {}
    artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
    path = _code_path(artifact.get("uri"))
    region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
    start = region.get("startLine") if isinstance(region.get("startLine"), int) and region["startLine"] > 0 else None
    end = region.get("endLine") if isinstance(region.get("endLine"), int) and region["endLine"] >= (start or 1) else None
    logical = None
    for ll in loc.get("logicalLocations") or []:
        if isinstance(ll, dict):
            logical = evidence.clean_line(ll.get("fullyQualifiedName") or ll.get("name"), 256)
            if logical:
                break
    if path is None:
        start = end = None
    return path, start, end, logical


def _flow(result: dict) -> list[dict]:
    steps: list[dict] = []
    for code_flow in (result.get("codeFlows") or [])[:1]:
        if not isinstance(code_flow, dict):
            continue
        for thread_flow in (code_flow.get("threadFlows") or [])[:1]:
            if not isinstance(thread_flow, dict):
                continue
            for tfl in (thread_flow.get("locations") or [])[:MAX_FLOW_STEPS]:
                if not isinstance(tfl, dict):
                    continue
                loc = tfl.get("location") if isinstance(tfl.get("location"), dict) else {}
                path, start, _, logical = _location(loc)
                kinds = [k for k in (str(x).lower() for x in tfl.get("kinds") or [])
                         if k in {"source", "sink", "sanitizer", "taint", "call", "return"}]
                step = {
                    "location": f"{path}:{start}" if path and start else path,
                    "function": logical,
                    "kinds": kinds[:4] or None,
                    "note": evidence.clean_line(redact.redact_text(_text(loc.get("message"))), 160),
                }
                if any(step.values()):
                    steps.append({k: v for k, v in step.items() if v})
    return steps


def _vendor_id(result: dict) -> str | None:
    candidates: list[Any] = [result.get("correlationGuid")]
    for key in ("partialFingerprints", "fingerprints"):
        prints = result.get(key)
        if isinstance(prints, dict) and prints:
            candidates.append("|".join(f"{k}={prints[k]}" for k in sorted(prints)))
    candidates.append(result.get("guid"))
    for c in candidates:
        if isinstance(c, str) and c and len(c) <= 512:
            value = c if _VENDOR_ID_RE.match(c) else sca.fingerprint("vendor-id", c)
            return value[:128]
    return None


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _https_link(value: Any) -> str | None:
    text = evidence.clean_line(value, 300)
    if not text:
        return None
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return None
    return urlunsplit(("https", parts.hostname.lower(), parts.path, "", ""))


def _session(value: Any) -> str | None:
    text = evidence.clean_line(value, 256)
    if not text:
        return None
    return _SESSION_RE.sub("-", text).strip("-")[:128] or None


def build_findings(report: Any, provider_id: str, project_id: str, pipeline_run_id: str,
                   test_session_id: str | None = None, environment: str | None = None) -> ImportedReport:
    provider = providers.PROVIDERS.get(provider_id)
    if provider is None:
        raise ReportRejected(
            f"unsupported provider '{provider_id}'; supported: {', '.join(sorted(providers.PROVIDERS))}")
    if not isinstance(report, dict):
        raise ReportRejected("report is not a SARIF log (expected a JSON object)")
    if report.get("version") != "2.1.0":
        raise ReportRejected(
            f"unsupported SARIF version {str(report.get('version'))[:20]!r}; only 2.1.0 is accepted")
    schema = report.get("$schema")
    if schema is not None and (not isinstance(schema, str) or "sarif" not in schema.lower()):
        raise ReportRejected("report $schema is not a SARIF schema")
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ReportRejected("report contains no runs")
    if len(runs) > MAX_RUNS:
        raise ReportRejected(f"report has {len(runs)} runs; at most {MAX_RUNS} are accepted")

    imported: ImportedReport | None = None
    env = evidence.clean_line(environment, 64)
    for run in runs:
        if not isinstance(run, dict):
            raise ReportRejected("report contains a malformed run")
        tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
        driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
        tool_name = evidence.clean_line(driver.get("name"), 128)
        if not tool_name:
            raise ReportRejected("run has no tool.driver.name, so the producing engine is unknown")
        full_name = evidence.clean_line(driver.get("fullName"), 256) or ""
        denied = providers.non_iast_tool(tool_name) or providers.non_iast_tool(full_name)
        if denied:
            raise ReportRejected(
                f"report was produced by '{tool_name}', a static/dependency/DAST tool, "
                "not an IAST engine; import it with `scan` or not at all")
        if provider.tool_name_pattern and not provider.tool_name_pattern.search(f"{tool_name} {full_name}"):
            raise ReportRejected(
                f"report was produced by '{tool_name}', which does not match provider '{provider.id}'")
        tool_version = evidence.clean_line(driver.get("semanticVersion") or driver.get("version"), 64)
        if imported is None:
            imported = ImportedReport(provider=provider, tool_name=tool_name, tool_version=tool_version)
        elif imported.tool_name != tool_name:
            raise ReportRejected("all runs in one IAST report must come from the same engine")

        if "results" not in run or run.get("results") is None:
            raise ReportRejected(
                "a run has no results array; SARIF uses that to say the analysis did not run")
        results = run["results"]
        if not isinstance(results, list):
            raise ReportRejected("run.results is not an array")
        imported.total_results += len(results)
        if imported.total_results > MAX_RESULTS:
            raise ReportRejected(f"report has more than {MAX_RESULTS} results")

        for inv in run.get("invocations") or []:
            if isinstance(inv, dict) and inv.get("executionSuccessful") is False:
                imported.warnings.append(f"{tool_name} reported an unsuccessful invocation")

        automation = run.get("automationDetails") if isinstance(run.get("automationDetails"), dict) else {}
        session = _session(test_session_id) or _session(automation.get("id"))
        imported.test_session = imported.test_session or session

        rules = _rule_index(tool)
        web_requests = run.get("webRequests") if isinstance(run.get("webRequests"), list) else []
        for result in results:
            finding = _finding(result, rules, web_requests, imported, provider, tool_name,
                               tool_version, session, env, project_id, pipeline_run_id)
            if finding:
                imported.findings.append(finding)

    assert imported is not None
    if imported.total_results and not imported.findings and imported.skipped_no_runtime_evidence:
        raise ReportRejected(
            f"none of the {imported.skipped_no_runtime_evidence} result(s) carry runtime evidence "
            "(result.webRequest). This looks like static-analysis output, not IAST.")
    if imported.skipped_no_runtime_evidence:
        imported.warnings.append(
            f"{imported.skipped_no_runtime_evidence} result(s) were skipped because they carry no "
            "runtime evidence (result.webRequest)")
    return imported


def _rule_index(tool: dict) -> dict[Any, dict]:
    index: dict[Any, dict] = {}
    components = [tool.get("driver")] + list(tool.get("extensions") or [])
    for ci, component in enumerate(components):
        if not isinstance(component, dict):
            continue
        for ri, rule in enumerate(component.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            if ci == 0:
                index[("index", ri)] = rule
            if isinstance(rule.get("id"), str):
                index.setdefault(("id", rule["id"]), rule)
    return index


def _finding(result: Any, rules: dict, web_requests: list, imported: ImportedReport,
             provider: providers.Provider, tool_name: str, tool_version: str | None,
             session: str | None, env: str | None, project_id: str, pipeline_run_id: str) -> dict | None:
    if not isinstance(result, dict):
        imported.skipped_not_findings += 1
        return None
    kind = str(result.get("kind") or "fail").lower()
    suppressed = any(isinstance(s, dict) and str(s.get("status", "accepted")).lower() == "accepted"
                     for s in result.get("suppressions") or [])
    if kind in _SKIPPED_KINDS or suppressed or str(result.get("baselineState", "")).lower() == "absent":
        imported.skipped_not_findings += 1
        return None

    request = result.get("webRequest") if isinstance(result.get("webRequest"), dict) else None
    if request is not None and isinstance(request.get("index"), int) and 0 <= request["index"] < len(web_requests):
        referenced = web_requests[request["index"]]
        request = {**referenced, **request} if isinstance(referenced, dict) else request
    route = redact.sanitize_route(request.get("target")) if request else None
    if not route:
        imported.skipped_no_runtime_evidence += 1
        return None
    method = redact.sanitize_method(request.get("method"))

    rule_index = result.get("ruleIndex")
    rule = (rules.get(("index", rule_index)) if isinstance(rule_index, int) else None) \
        or rules.get(("id", result.get("ruleId"))) or {}
    raw_rule_id = result.get("ruleId") or rule.get("id") or "IAST"
    rule_id = (_RULE_ID_SAFE_RE.sub("-", evidence.clean_line(raw_rule_id, 256) or "IAST").strip("-") or "IAST")

    title = evidence.clean_line(redact.redact_text(
        _text(rule.get("shortDescription")) or rule.get("name") or rule_id), 200)
    category = evidence.clean_line(rule.get("name") or _text(rule.get("shortDescription")), 120)
    message = evidence.clean_text(redact.redact_text(_text(result.get("message"))), 1_000)
    remediation = evidence.clean_text(redact.redact_text(
        _text(rule.get("help")) or _text(rule.get("fullDescription"))), 1_500)
    severity, severity_source, score = _severity(result, rule)
    cwes = _cwes(result, rule)

    locations = result.get("locations") or []
    path, start, end, logical = _location(locations[0] if locations else None)
    vendor_id = _vendor_id(result)
    provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
    tool_key = tool_name.lower()

    if vendor_id:
        fp = sca.fingerprint(SCANNER_KEY, provider.id, tool_key, vendor_id)
    else:
        fp = sca.fingerprint(SCANNER_KEY, provider.id, tool_key, rule_id, method or "", route, path or "", start or "")

    where = f"{method} {route}" if method else route
    headline = f"{title} at {where}."
    description = headline if not message else f"{headline}\n\n{message}"

    payload = evidence.envelope("iast", {
        "testingMethod": "IAST",
        "provider": provider.id,
        "providerName": provider.display_name,
        "providerVerified": provider.verified,
        "tool": tool_name,
        "toolVersion": tool_version,
        "ruleId": rule_id,
        "title": title,
        "category": category,
        "severity": severity,
        "severitySource": severity_source,
        "cvssScore": score,
        "cweIds": cwes,
        "method": method,
        "route": route,
        "codePath": path,
        "codeStartLine": start,
        "codeEndLine": end,
        "codeFunction": logical,
        "flow": _flow(result),
        "message": message,
        "remediation": remediation,
        "helpUrl": _https_link(rule.get("helpUri")),
        "vendorFindingId": vendor_id,
        "testSession": session,
        "environment": env,
        "firstObservedAt": _timestamp(provenance.get("firstDetectionTimeUtc")),
        "lastObservedAt": _timestamp(provenance.get("lastDetectionTimeUtc")),
    })

    return {
        "scanner": SCANNER_KEY,
        "ruleId": rule_id,
        "filePath": path,
        "codeSnippet": None,
        "severity": severity or "UNKNOWN",
        "description": evidence.clean_text(description, evidence.MAX_DESCRIPTION_CHARS),
        "cweIds": cwes or None,
        "owaspCategories": None,
        "startLine": start,
        "endLine": end,
        "projectId": project_id,
        "pipelineRunId": pipeline_run_id,
        "fingerprint": fp,
        "rawPayload": payload,
    }
