import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request

import api_client

from .common import (
    MARKER,
    build_summary,
    finding_line,
    inline_body,
    normalize_path,
    parse_patch_lines,
    should_inline,
)

log = logging.getLogger(__name__)

_GH_API = "https://api.github.com"
# Cap inline comments so a noisy run can't post hundreds of review comments.
# Anything beyond the cap is still counted in the summary.
_MAX_INLINE = 50


def _gh_request(
    url: str,
    token: str,
    method: str = "GET",
    body: dict | None = None,
    critical: bool = True,
):
    """Call the GitHub API. When ``critical`` is False, errors are logged and
    ``None`` is returned instead of exiting — used for the best-effort inline
    annotation so a failure there never blocks the summary comment."""
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:300]
        if e.code == 403:
            log.warning("PR comment: 403 Forbidden — tenant may not support PR comments on this tier. Skipping.")
            return None
        if not critical:
            log.warning("GitHub API %s %s returned %d: %s", method, url, e.code, body_text)
            return None
        log.exception("GitHub API %s %s returned %d: %s", method, url, e.code, body_text)
        sys.exit(2)
    except urllib.error.URLError as e:
        if not critical:
            log.warning("GitHub API %s %s failed: %s", method, url, e)
            return None
        raise


def _get_pr_number() -> str | None:
    ref = os.environ.get("GITHUB_REF", "")
    m = re.match(r"refs/pull/(\d+)/", ref)
    if m:
        return m.group(1)

    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_path:
        try:
            with open(event_path, encoding="utf-8") as f:
                event = json.load(f)
            pr_number = event.get("pull_request", {}).get("number")
            if pr_number:
                return str(pr_number)
        except Exception:
            pass

    return None


def _commentable_lines(repo: str, pr_number: str, token: str) -> dict[str, set[int]]:
    """Map each changed file to the set of new-file line numbers a review comment
    may target (GitHub rejects comments on lines outside the diff)."""
    result: dict[str, set[int]] = {}
    page = 1
    while True:
        url = f"{_GH_API}/repos/{repo}/pulls/{pr_number}/files?per_page=100&page={page}"
        files = _gh_request(url, token, critical=False)
        if not files:
            break
        for f in files:
            filename = f.get("filename")
            patch = f.get("patch")
            if filename and patch:
                result[filename] = parse_patch_lines(patch)
        if len(files) < 100:
            break
        page += 1
    return result


def _build_inline_comments(findings: list[dict], commentable: dict[str, set[int]]) -> list[dict]:
    """Inline review-comment payloads for high-signal findings that land on
    changed lines, de-duplicated by (path, line, rule)."""
    comments: list[dict] = []
    seen: set[tuple] = set()
    for finding in findings:
        if not should_inline(finding):
            continue
        path = normalize_path(finding.get("filePath"))
        line = finding_line(finding)
        if not path or line is None:
            continue
        if line not in commentable.get(path, set()):
            continue
        key = (path, line, finding.get("ruleId"))
        if key in seen:
            continue
        seen.add(key)
        comments.append({"path": path, "line": line, "side": "RIGHT", "body": inline_body(finding)})
    return comments


def _prior_inline_comment_ids(repo: str, pr_number: str, token: str) -> list[int]:
    """IDs of SecureObs review comments left by earlier runs."""
    ids: list[int] = []
    page = 1
    while True:
        url = f"{_GH_API}/repos/{repo}/pulls/{pr_number}/comments?per_page=100&page={page}"
        comments = _gh_request(url, token, critical=False)
        if not comments:
            break
        ids.extend(c["id"] for c in comments if MARKER in (c.get("body") or ""))
        if len(comments) < 100:
            break
        page += 1
    return ids


def _delete_inline_comments(repo: str, token: str, ids: list[int]) -> None:
    for cid in ids:
        _gh_request(f"{_GH_API}/repos/{repo}/pulls/comments/{cid}", token, method="DELETE", critical=False)


def _post_inline_review(repo: str, pr_number: str, token: str, comments: list[dict]) -> tuple[bool, int]:
    """Post a single COMMENT review carrying all inline comments. Returns
    ``(ok, count)``; ``ok`` is False only when a non-empty review failed to post,
    so the caller can avoid deleting the previous run's comments in that case."""
    if not comments:
        return True, 0
    url = f"{_GH_API}/repos/{repo}/pulls/{pr_number}/reviews"
    result = _gh_request(url, token, method="POST", body={"event": "COMMENT", "comments": comments}, critical=False)
    if result is None:
        return False, 0
    log.info("Posted %d inline PR comment(s).", len(comments))
    return True, len(comments)


def _upsert_summary(repo: str, pr_number: str, token: str, comment_body: str) -> None:
    comments_url = f"{_GH_API}/repos/{repo}/issues/{pr_number}/comments"
    existing_comments = _gh_request(comments_url, token) or []

    existing_comment_id = None
    for c in existing_comments:
        if MARKER in (c.get("body") or ""):
            existing_comment_id = c["id"]
            break

    if existing_comment_id:
        patch_url = f"{_GH_API}/repos/{repo}/issues/comments/{existing_comment_id}"
        result = _gh_request(patch_url, token, method="PATCH", body={"body": comment_body})
        if result is not None:
            log.info("PR summary comment updated (comment %s).", existing_comment_id)
    else:
        result = _gh_request(comments_url, token, method="POST", body={"body": comment_body})
        if result is not None:
            log.info("PR summary comment posted.")


def post_or_update(
    api_url: str,
    api_key: str,
    pipeline_run_id: str,
    project_id: str | None = None,
) -> None:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name != "pull_request":
        log.info("Not a pull_request event (got '%s') — skipping PR comment.", event_name)
        return

    pr_number = _get_pr_number()
    if not pr_number:
        log.warning("Could not determine PR number — skipping PR comment.")
        return

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GH_TOKEN", "")

    if not all([repo, token]):
        log.warning("Missing GH_TOKEN or GITHUB_REPOSITORY — skipping PR comment.")
        return

    is_blocking = _fetch_blocking(api_url, api_key, pipeline_run_id)

    # Best-effort inline annotation. Any failure here falls back to the summary
    # comment alone — PR decoration must never break a customer's pipeline.
    total: int | None = None
    inline_count = 0
    findings = (
        api_client.get_pr_findings(api_url, api_key, project_id, pipeline_run_id)
        if project_id
        else None
    )
    if findings is not None:
        total = len(findings)
        try:
            # Capture the previous run's comment IDs *before* posting so we can
            # remove them afterwards — and only if the new review posts cleanly,
            # so a failed post never strips existing annotations.
            prior_ids = _prior_inline_comment_ids(repo, pr_number, token)
            commentable = _commentable_lines(repo, pr_number, token)
            inline_comments = _build_inline_comments(findings, commentable)[:_MAX_INLINE]
            posted_ok, inline_count = _post_inline_review(repo, pr_number, token, inline_comments)
            if posted_ok:
                _delete_inline_comments(repo, token, prior_ids)
        except Exception as e:  # noqa: BLE001 - decoration is best-effort
            log.warning("Inline PR annotation failed (%s); posting summary only.", e)

    _upsert_summary(repo, pr_number, token, build_summary(is_blocking, total=total, inline_count=inline_count))


def _fetch_blocking(api_url: str, api_key: str, pipeline_run_id: str) -> bool:
    url = f"{api_url}/findings/blocking?pipelineRunId={pipeline_run_id}"
    req = urllib.request.Request(url, headers={"X-Api-Key": api_key})
    try:
        with urllib.request.urlopen(req) as resp:
            return bool(json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        log.warning("Could not fetch blocking status (%d) — assuming not blocking.", e.code)
        return False
