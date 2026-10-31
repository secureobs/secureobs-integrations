"""Optional CycloneDX SBOM via the bundled Trivy (``scan --sbom-output``).

The SBOM is written inside the CI job only. It is never uploaded to SecureObs:
it lists every package Trivy found, which is the customer's inventory to keep
or publish as they choose (typically as a CI build artifact).

Trivy's ``--format cyclonedx`` produces an inventory-only BOM (no vulnerability
data) — verified with Trivy 0.70.0, which emits CycloneDX 1.6.
"""
from __future__ import annotations

import logging
import subprocess

from . import tool_output

log = logging.getLogger(__name__)


def build_command(source_dir: str, output_path: str) -> list[str]:
    return ["trivy", "fs", "--format", "cyclonedx", "--output", output_path, source_dir]


def generate(source_dir: str, output_path: str) -> int:
    """Write the SBOM and return its component count. Raises on any failure."""
    tool_output.remove_stale(output_path)
    try:
        proc = subprocess.run(build_command(source_dir, output_path), capture_output=True, text=True,
                              timeout=tool_output.TOOL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("SBOM generation timed out") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"trivy exited with code {proc.returncode}: {tool_output.stderr_tail(proc.stderr)}")
    data = tool_output.load_json_output(output_path, "trivy (cyclonedx)")
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise tool_output.ToolOutputError("trivy did not produce a CycloneDX document")
    components = data.get("components") or []
    log.info("SBOM written to %s (CycloneDX %s, %d component(s)). It stays in this CI job; "
             "SecureObs does not upload it.", output_path, data.get("specVersion"), len(components))
    return len(components)
