"""``secureobs-scanner import-iast`` — import a report produced by an IAST agent.

The image does not run or instrument the application. The customer's own test
job runs the app with an IAST agent attached, exports a report, mounts it into
this container read-only, and this command validates, sanitizes and uploads it
through the existing authenticated ingestion API.

Exit codes (deterministic, documented in the README):
  0  imported (including a valid report with zero findings)
  1  configuration/authorization problem (missing key, wrong project, IAST not
     enabled for the project, untrusted fork pull request, bad arguments)
  2  SecureObs API or network failure — safe to retry; imports are idempotent
  5  report missing or unreadable
  6  report rejected (invalid SARIF, unsupported version, oversized, produced by
     a non-IAST tool, or no runtime evidence)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Mapping

import api_client
import execution

from . import providers, sarif

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_API = 2
EXIT_REPORT_MISSING = 5
EXIT_REPORT_REJECTED = 6

_BULK_UNIVERSAL = "findings/bulk-universal"
_MAX_EVENT_FILE_BYTES = 5 * 1024 * 1024


def untrusted_pr_context(env: Mapping[str, str] | None = None) -> str | None:
    """Why this run must not import, or None. Defense in depth only: the CI job
    itself must already keep secrets away from fork pull requests."""
    env = os.environ if env is None else env
    if str(env.get("SYSTEM_PULLREQUEST_ISFORK", "")).lower() == "true":
        return "this Azure DevOps run was triggered by a pull request from a fork"
    event = env.get("GITHUB_EVENT_NAME", "")
    if not event.startswith("pull_request"):
        return None
    path = env.get("GITHUB_EVENT_PATH")
    payload = None
    if path:
        try:
            if os.path.getsize(path) <= _MAX_EVENT_FILE_BYTES:
                with open(path, encoding="utf-8") as fh:
                    payload = json.load(fh)
        except (OSError, ValueError):
            payload = None
    if not isinstance(payload, dict):
        if event == "pull_request_target":
            return ("a pull_request_target run cannot prove the pull request's origin "
                    "(mount GITHUB_EVENT_PATH into the container)")
        return None
    pr = payload.get("pull_request") or {}
    head = ((pr.get("head") or {}).get("repo") or {})
    base = ((pr.get("base") or {}).get("repo") or {})
    if head.get("fork") is True or (
            head.get("full_name") and base.get("full_name") and head["full_name"] != base["full_name"]):
        return "this GitHub run was triggered by a pull request from a fork"
    return None


def _report_status(api_url: str, api_key: str, args, status: str, *, reason: str | None = None,
                   detail: str | None = None, count: int = 0, session: str | None = None) -> bool:
    row = execution.Execution(
        key=sarif.SCANNER_KEY, status=status, finding_count=count, reason_code=reason,
        detail=execution.safe_detail(detail), provider=args.provider, test_session=session)
    return api_client.post_scan_executions(api_url, api_key, args.project_id, args.pipeline_run_id,
                                           [row.to_api()])


def run(args, api_url: str, api_key: str) -> int:
    reason = untrusted_pr_context()
    if reason:
        log.error("Refusing to import an IAST report: %s. Run IAST imports only from trusted "
                  "branches or same-repository pull requests.", reason)
        return EXIT_CONFIG

    if not (1024 <= args.max_report_bytes <= sarif.HARD_MAX_REPORT_BYTES):
        log.error("--max-report-bytes must be between 1024 and %d.", sarif.HARD_MAX_REPORT_BYTES)
        return EXIT_CONFIG

    provider = providers.PROVIDERS[args.provider]
    if not provider.verified:
        log.warning("Provider '%s' is UNVERIFIED. %s", provider.id, provider.note)

    try:
        report = sarif.load_report(args.file, args.max_report_bytes)
        imported = sarif.build_findings(report, args.provider, args.project_id, args.pipeline_run_id,
                                        test_session_id=args.test_session_id, environment=args.environment)
    except sarif.ReportMissing as exc:
        log.error("IAST report missing: %s. Did the instrumented test run produce a report?", exc)
        _report_status(api_url, api_key, args, execution.FAILED, reason="report_missing",
                       detail="The IAST report file was not found in the CI job.")
        return EXIT_REPORT_MISSING
    except sarif.ReportRejected as exc:
        log.error("IAST report rejected: %s", exc)
        _report_status(api_url, api_key, args, execution.FAILED, reason="report_rejected",
                       detail=str(exc))
        return EXIT_REPORT_REJECTED

    log.info(
        "IAST report: %s%s via provider '%s'%s — %d result(s), %d finding(s) with runtime evidence, "
        "%d skipped without runtime evidence, %d non-findings (pass/suppressed/absent).",
        imported.tool_name, f" {imported.tool_version}" if imported.tool_version else "",
        provider.id, "" if provider.verified else " (UNVERIFIED)",
        imported.total_results, len(imported.findings), imported.skipped_no_runtime_evidence,
        imported.skipped_not_findings)
    for warning in imported.warnings:
        log.warning("%s", warning)

    new_count = 0
    if imported.findings:
        try:
            result = api_client.post_findings_checked(api_url, api_key, _BULK_UNIVERSAL, imported.findings)
        except api_client.ApiAuthError:
            log.error("Authentication failed — check SECUREOBS_API_KEY.")
            return EXIT_CONFIG
        except api_client.ApiError as exc:
            if exc.transient or exc.status is None:
                log.error("Upload failed (%s). Re-running this step is safe: imports are idempotent.", exc)
                _report_status(api_url, api_key, args, execution.FAILED, reason="upload_failed",
                               detail="The report was valid but uploading it to SecureObs failed.")
                return EXIT_API
            if exc.code == "iast_not_enabled":
                log.error("IAST is not enabled for this project. Turn on 'Interactive testing (IAST)' "
                          "in the project's scanner settings first.")
            else:
                log.error("SecureObs refused the import: %s", exc)
            return EXIT_CONFIG
        deduplicated = result.get("deduplicated")
        new_count = None if deduplicated is None else max(int(result.get("ingested", 0)) - int(deduplicated), 0)

    status = execution.COMPLETED if imported.findings else execution.COMPLETED_NO_FINDINGS
    detail = f"{imported.tool_name} {imported.tool_version or ''}".strip()
    row = execution.Execution(
        key=sarif.SCANNER_KEY, status=status, finding_count=len(imported.findings),
        detail=execution.safe_detail(detail), provider=args.provider, test_session=imported.test_session)
    try:
        api_client.post_scan_executions_checked(api_url, api_key, args.project_id,
                                                args.pipeline_run_id, [row.to_api()])
    except api_client.ApiError as exc:
        if exc.code == "iast_not_enabled":
            log.error("IAST is not enabled for this project. Turn on 'Interactive testing (IAST)' "
                      "in the project's scanner settings first.")
            return EXIT_CONFIG
        if isinstance(exc, api_client.ApiAuthError) or (exc.status in (400, 403) and not exc.transient):
            log.error("SecureObs refused the import status: %s", exc)
            return EXIT_CONFIG
        log.error("The import status could not be recorded (%s); the build gate would treat this "
                  "report as missing. Re-run this step — imports are idempotent.", exc)
        return EXIT_API

    if new_count is None:
        log.info("IAST import complete: %d finding(s) uploaded.", len(imported.findings))
    else:
        log.info("IAST import complete: %d finding(s) uploaded (%d new).", len(imported.findings), new_count)
    return EXIT_OK
