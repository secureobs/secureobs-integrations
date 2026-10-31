"""Bounded, strict reading of scanner tool output.

A tool that exits successfully but leaves no output, truncated JSON, or a
multi-gigabyte file is a *failed* scan, never a clean one. Everything here
raises ``ToolOutputError`` so ``cli.py`` records the scanner as failed.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

# Real Trivy/OSV reports for large monorepos are tens of MiB; this bound only
# stops a runaway or hostile file from exhausting the CI runner's memory.
MAX_TOOL_OUTPUT_BYTES = int(os.environ.get("SECUREOBS_MAX_TOOL_OUTPUT_BYTES", 256 * 1024 * 1024))
# Upper bound on a single tool invocation; a hung scanner must not hang CI.
TOOL_TIMEOUT_SECONDS = int(os.environ.get("SECUREOBS_TOOL_TIMEOUT_SECONDS", 30 * 60))

# Whole ANSI escape sequences first, so "\x1b[31m" is removed entirely rather
# than leaving "[31m" behind after the bare ESC is stripped.
_CONTROL_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f]")


class ToolOutputError(RuntimeError):
    """The tool ran but its output cannot be trusted."""


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def load_json_output(path: str, tool: str, max_bytes: int | None = None) -> Any:
    limit = MAX_TOOL_OUTPUT_BYTES if max_bytes is None else max_bytes
    if not os.path.isfile(path):
        raise ToolOutputError(f"{tool} reported success but wrote no output file")
    size = os.path.getsize(path)
    if size == 0:
        raise ToolOutputError(f"{tool} wrote an empty output file")
    if size > limit:
        raise ToolOutputError(
            f"{tool} output is {size} bytes, above the {limit}-byte safety limit")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh, parse_constant=_reject_constant)
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise ToolOutputError(f"{tool} output is not valid JSON ({type(exc).__name__})") from exc


def stderr_tail(stderr: str | None, limit: int = 600) -> str:
    """Last ``limit`` characters of stderr with control/ANSI sequences removed."""
    text = _CONTROL_RE.sub("", (stderr or "").replace("\r", ""))
    lines = [ln for ln in text.splitlines()
             if ln.strip() and "Failed to resolve gitignore" not in ln]
    return "\n".join(lines)[-limit:]


def remove_stale(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
