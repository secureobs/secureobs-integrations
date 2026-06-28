"""Platform-agnostic helpers shared by the GitHub and Azure DevOps PR-comment
posters.

The posting flow has two layers:

* a single **summary** comment (upserted via ``MARKER``) that states whether the
  pipeline is blocked and links to the dashboard, and
* **inline** comments anchored to the exact file/line of high-signal findings
  that land on lines the pull request actually changed.

Inline comments are only valid on lines that are part of the PR diff (both
GitHub and Azure reject comments on untouched lines), so the helpers here parse
the diff and filter findings accordingly. Everything in this module is pure and
unit-tested; the platform modules own the HTTP.
"""

MARKER = "<!-- secureobs-scanner -->"

DASHBOARD_URL = "https://secureobs-dashboard.azurewebsites.net"

# Severities worth an inline comment. Blocking findings are always included
# regardless of severity. Everything else is rolled into the summary so noisy
# scanners can't flood a PR.
INLINE_SEVERITIES = {"CRITICAL", "HIGH"}

_SEVERITY_EMOJI = {"CRITICAL": "⛔", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}


def normalize_path(path: str | None) -> str:
    """Return a repo-relative POSIX path for a scanner-reported file.

    Scanners run against the workspace mount, so paths can arrive as
    ``/workspace/src/A.cs``, ``./src/A.cs`` or already-relative. GitHub/ADO want
    the path exactly as it appears in the repo tree.
    """
    if not path:
        return ""
    p = path.replace("\\", "/")
    for prefix in ("/workspace/", "workspace/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    return p.lstrip("/")


def finding_line(finding: dict) -> int | None:
    """The line an inline comment should anchor to (start line, else end line)."""
    start = finding.get("startLine")
    if isinstance(start, int) and start > 0:
        return start
    end = finding.get("endLine")
    if isinstance(end, int) and end > 0:
        return end
    return None


def should_inline(finding: dict) -> bool:
    """True if a finding is high-signal enough to warrant an inline comment."""
    if finding.get("isBlocking"):
        return True
    severity = (finding.get("severity") or "").upper()
    return severity in INLINE_SEVERITIES


def parse_patch_lines(patch: str | None) -> set[int]:
    """Return the set of new-file (RIGHT-side) line numbers a unified diff
    ``patch`` makes commentable — i.e. added and context lines within hunks.

    GitHub's ``GET /pulls/{n}/files`` and ADO's iteration changes expose this
    per-file patch text. A comment on any other line is rejected by the API.
    """
    commentable: set[int] = set()
    if not patch:
        return commentable

    new_line = 0
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            # @@ -old,oldcount +new,newcount @@
            try:
                plus = raw.split("+", 1)[1]
                new_start = plus.split(",", 1)[0].split(" ", 1)[0]
                new_line = int(new_start)
            except (IndexError, ValueError):
                new_line = 0
            continue
        if new_line == 0:
            continue
        if raw.startswith(("-", "\\")):
            # A removed line is absent from the new file; "\ No newline at end
            # of file" is a marker, not a line. Neither is commentable.
            continue
        # An added ("+") or context (leading-space / empty) line exists in the
        # new file at new_line and can be commented on.
        commentable.add(new_line)
        new_line += 1
    return commentable


def inline_body(finding: dict) -> str:
    """Markdown body for a single inline finding comment. Carries ``MARKER`` so
    prior SecureObs comments can be found and replaced on re-runs."""
    severity = (finding.get("severity") or "UNKNOWN").upper()
    rule = finding.get("ruleId") or "finding"
    scanner = finding.get("scanner") or "secureobs"
    emoji = _SEVERITY_EMOJI.get(severity, "•")
    body = f"{MARKER}\n**{emoji} SecureObs · {severity}** — `{rule}` ({scanner})"
    description = (finding.get("description") or "").strip()
    if description:
        body += f"\n\n{description}"
    body += f"\n\n_[View in SecureObs dashboard]({DASHBOARD_URL})_"
    return body


def _summary_detail(total: int, inline_count: int) -> str:
    """One-line breakdown of findings for the summary comment."""
    if total == 0:
        return "No findings on this pull request. 🎉"

    inline_n = inline_count or 0
    elsewhere = total - inline_n
    detail = f"**{total}** open finding{'s' if total != 1 else ''} on this run"
    if inline_n:
        detail += f" — **{inline_n}** commented inline on changed lines"
    if elsewhere > 0:
        # The remainder is anything not annotated inline: lower-severity findings,
        # findings on lines the PR didn't change, or any beyond the inline cap.
        joiner = ";" if inline_n else " —"
        detail += f"{joiner} **{elsewhere}** not shown inline (lower severity or unchanged lines) — see the dashboard"
    return detail + "."


def build_summary(
    is_blocking: bool,
    *,
    total: int | None = None,
    inline_count: int | None = None,
) -> str:
    """The single upserted summary comment. ``total`` is the number of open
    findings with a location; ``inline_count`` how many were annotated inline."""
    if is_blocking:
        status = (
            "⛔ **Pipeline blocked** — critical findings detected. "
            "Resolve all blocking findings before merging."
        )
    else:
        status = "✅ No blocking findings detected."

    lines = [MARKER, "## SecureObs Security Scan", "", status, ""]
    if total is not None:
        lines.append(_summary_detail(total, inline_count or 0))
        lines.append("")
    lines.append(f"_View full details in your [SecureObs dashboard]({DASHBOARD_URL})._")
    return "\n".join(lines)
