from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    # Populated when skipped due to a non-zero tool exit so cli.py can
    # surface the failure at ERROR level with full diagnostic context.
    exit_code: int | None = None
    stderr_tail: str = ""
    # True when the tool ran correctly but found nothing it can analyse (no
    # lockfiles for an SCA scanner, no JavaScript for ESLint). Distinguishes
    # "not applicable" from both a clean scan and a failed one.
    not_applicable: bool = False
    # SCA only: number of dependency manifests / lockfiles the tool analysed.
    # None for scanners where the concept does not apply.
    sources_analyzed: int | None = None
    # Non-fatal problems worth surfacing (e.g. one lockfile could not be parsed
    # while the others were scanned). Plain text, never tool output verbatim.
    warnings: list[str] = field(default_factory=list)
