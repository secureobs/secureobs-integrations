"""Per-scanner execution outcomes for one pipeline run.

The scanner image reports these to ``POST /api/scan-executions`` so the
server-side gate can tell "ran and found nothing" from "never ran" and from
"crashed". Wire values match ``ScanExecutionStatus`` in SecureObs.Domain.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from iast import redact
from scanners import evidence
from scanners.base import ScanResult

log = logging.getLogger(__name__)

RUNNING = "running"
COMPLETED = "completed"
COMPLETED_NO_FINDINGS = "completed_no_findings"
SKIPPED_NOT_APPLICABLE = "skipped_not_applicable"
SKIPPED_NOT_CONFIGURED = "skipped_not_configured"
FAILED = "failed"

_LABELS = {
    RUNNING: "RUNNING",
    COMPLETED: "",
    COMPLETED_NO_FINDINGS: "0 findings",
    SKIPPED_NOT_APPLICABLE: "NOT APPLICABLE",
    SKIPPED_NOT_CONFIGURED: "NOT CONFIGURED",
    FAILED: "FAILED",
}


def _reason(text: str | None) -> str | None:
    """Machine reason codes are lowercase snake_case, ≤ 64 chars."""
    if not text:
        return None
    code = "".join(c if c.isalnum() else "_" for c in text.lower()).strip("_")
    while "__" in code:
        code = code.replace("__", "_")
    return code[:64] or None


def safe_detail(text: str | None) -> str | None:
    """Human detail for the dashboard: redacted, single line, short."""
    return evidence.clean_line(redact.redact_text(text), 300)


@dataclass
class Execution:
    key: str
    status: str
    finding_count: int = 0
    # None when the API did not report how many uploaded findings were merged.
    new_after_dedup: int | None = None
    sources_analyzed: int | None = None
    reason_code: str | None = None
    detail: str | None = None
    provider: str | None = None
    test_session: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_api(self) -> dict:
        return {
            "scannerKey": self.key,
            "status": self.status,
            "findingCount": self.finding_count,
            "sourcesAnalyzed": self.sources_analyzed,
            "reasonCode": self.reason_code,
            "detail": self.detail,
            "provider": self.provider,
            "testSession": self.test_session,
        }


def running(key: str) -> Execution:
    return Execution(key=key, status=RUNNING)


def driver_unavailable(key: str) -> Execution:
    return Execution(key=key, status=SKIPPED_NOT_CONFIGURED, reason_code="driver_unavailable",
                     detail="This scanner image has no driver for this scanner; pin a newer image tag.")


def from_exception(key: str, exc: BaseException) -> Execution:
    return Execution(key=key, status=FAILED, reason_code="tool_error",
                     detail=safe_detail(f"{type(exc).__name__}: {exc}"))


def from_result(key: str, result: ScanResult) -> Execution:
    """Outcome before upload. ``COMPLETED`` rows get counts once ingestion succeeds."""
    warnings = [w for w in (safe_detail(w) for w in result.warnings) if w]
    if result.skipped:
        if result.not_applicable:
            return Execution(key=key, status=SKIPPED_NOT_APPLICABLE, sources_analyzed=result.sources_analyzed,
                             reason_code=_reason(result.skip_reason) or "not_applicable",
                             detail=warnings[0] if warnings else safe_detail(result.skip_reason),
                             warnings=warnings)
        reason = f"tool_exit_{result.exit_code}" if result.exit_code is not None else result.skip_reason
        return Execution(key=key, status=FAILED, reason_code=_reason(reason) or "skipped",
                         detail=safe_detail(result.skip_reason), warnings=warnings)
    status = COMPLETED if result.findings else COMPLETED_NO_FINDINGS
    detail = "; ".join(warnings)[:300] if warnings else None
    reason = "no_supported_manifests" if result.sources_analyzed == 0 else None
    return Execution(key=key, status=status, finding_count=len(result.findings),
                     sources_analyzed=result.sources_analyzed, reason_code=reason,
                     detail=detail, warnings=warnings)


def print_summary(rows: list[Execution]) -> None:
    if not rows:
        return
    col_w = max(len(r.key) for r in rows) + 2
    sep = "─" * (col_w + 52)
    lines = [f"\n{sep}"]
    for r in rows:
        label = r.key.ljust(col_w)
        if r.status == COMPLETED:
            text = f"{r.finding_count} finding(s)"
            if r.new_after_dedup is not None:
                text += f"  ({r.new_after_dedup} new after dedup)"
        elif r.status == FAILED:
            text = f"FAILED   ({r.reason_code or 'error'}; see above)"
        elif r.status in (SKIPPED_NOT_APPLICABLE, SKIPPED_NOT_CONFIGURED):
            text = f"{_LABELS[r.status]}  ({r.detail or r.reason_code or 'no reason'})"
        else:
            text = _LABELS.get(r.status, r.status)
        if r.sources_analyzed is not None and r.status in (COMPLETED, COMPLETED_NO_FINDINGS):
            text += f"  · {r.sources_analyzed} dependency source(s)"
        lines.append(f"  {label}{text}")
        for w in r.warnings:
            lines.append(f"  {' ' * col_w}⚠ {w}")
    total = sum(r.finding_count for r in rows if r.status == COMPLETED)
    reported_new = [r.new_after_dedup for r in rows if r.new_after_dedup is not None]
    failed = [r.key for r in rows if r.status == FAILED]
    lines.append(sep)
    total_text = f"{total} finding(s) uploaded"
    if reported_new:
        total_text += f"  ({sum(reported_new)} new after dedup)"
    lines.append(f"  {'Total'.ljust(col_w)}{total_text}")
    if failed:
        lines.append(f"  {'Failed'.ljust(col_w)}{', '.join(failed)} — a failed scanner is not a clean result")
    lines.append(sep)
    log.info("\n".join(lines))
