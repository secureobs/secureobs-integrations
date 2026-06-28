import base64
import json
import logging
import os
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
    should_inline,
)

log = logging.getLogger(__name__)

_API_VERSION = "api-version=7.1-preview.1"
# Cap inline threads so a noisy run can't flood a PR.
_MAX_INLINE = 50


def _auth_header(token: str) -> str:
    encoded = base64.b64encode(f":{token}".encode()).decode()
    return f"Basic {encoded}"


def _ado_request(
    url: str,
    token: str,
    method: str = "GET",
    body: dict | None = None,
    critical: bool = True,
):
    """Call the Azure DevOps REST API. With ``critical=False`` errors are logged
    and ``None`` returned instead of exiting — used for best-effort inline
    annotation so it never blocks the summary comment."""
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": _auth_header(token),
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:300]
        if e.code == 403:
            log.warning("PR comment: 403 Forbidden — the build service likely lacks 'Contribute to pull requests'. Skipping.")
            return None
        if not critical:
            log.warning("ADO API %s %s returned %d: %s", method, url, e.code, body_text)
            return None
        log.exception("ADO API %s %s returned %d: %s", method, url, e.code, body_text)
        sys.exit(2)
    except urllib.error.URLError as e:
        if not critical:
            log.warning("ADO API %s %s failed: %s", method, url, e)
            return None
        raise


class _AdoContext:
    """Resolved Azure DevOps PR coordinates pulled from the pipeline environment."""

    def __init__(self) -> None:
        self.pr_id = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID")
        collection = os.environ.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "").rstrip("/")
        project = os.environ.get("SYSTEM_TEAMPROJECT", "")
        repo_id = os.environ.get("BUILD_REPOSITORY_ID", "")
        self.token = os.environ.get("SYSTEM_ACCESSTOKEN", "")
        self.base = f"{collection}/{project}/_apis/git/repositories/{repo_id}/pullRequests/{self.pr_id}"
        self.complete = all([collection, project, repo_id, self.token, self.pr_id])

    def threads_url(self) -> str:
        return f"{self.base}/threads?{_API_VERSION}"

    def thread_comment_url(self, thread_id, comment_id) -> str:
        return f"{self.base}/threads/{thread_id}/comments/{comment_id}?{_API_VERSION}"

    def thread_url(self, thread_id) -> str:
        return f"{self.base}/threads/{thread_id}?{_API_VERSION}"


def _changed_paths(ctx: _AdoContext) -> set[str]:
    """Repo-root paths (leading slash) changed in the PR's latest iteration.
    Azure only accepts inline threads on files that are part of the PR."""
    iters = _ado_request(f"{ctx.base}/iterations?{_API_VERSION}", ctx.token, critical=False)
    if not iters or not iters.get("value"):
        return set()
    iteration_id = iters["value"][-1]["id"]
    # $compareTo=0 compares the latest iteration against the merge base, i.e. the
    # cumulative PR diff — not just the most recent push's delta.
    changes = _ado_request(
        f"{ctx.base}/iterations/{iteration_id}/changes?{_API_VERSION}&$compareTo=0", ctx.token, critical=False
    )
    if not changes:
        return set()
    paths: set[str] = set()
    for entry in changes.get("changeEntries", []):
        path = (entry.get("item") or {}).get("path")
        if path:
            paths.add(path)
    return paths


def _find_summary_thread(threads: list[dict]):
    """Return (thread_id, comment_id) of the existing SecureObs summary thread —
    the one carrying MARKER but no file anchor — or (None, None)."""
    for thread in threads:
        if thread.get("threadContext"):
            continue
        for comment in thread.get("comments", []):
            if MARKER in (comment.get("content") or ""):
                return thread["id"], comment["id"]
    return None, None


def _prior_inline_thread_comments(threads: list[dict]) -> list[tuple]:
    """(thread_id, comment_id) pairs for SecureObs inline threads (MARKER + a file
    anchor) left by earlier runs."""
    out: list[tuple] = []
    for thread in threads:
        if not thread.get("threadContext"):
            continue
        for comment in thread.get("comments", []):
            if MARKER in (comment.get("content") or ""):
                out.append((thread["id"], comment["id"]))
    return out


def _delete_inline_threads(ctx: _AdoContext, items: list[tuple]) -> None:
    for thread_id, comment_id in items:
        _ado_request(ctx.thread_comment_url(thread_id, comment_id), ctx.token, method="DELETE", critical=False)


def _post_inline_threads(ctx: _AdoContext, findings: list[dict], changed: set[str]) -> int:
    """Create one inline thread per high-signal finding on a changed file.
    Returns the number posted."""
    posted = 0
    seen: set[tuple] = set()
    for finding in findings:
        if posted >= _MAX_INLINE:
            break
        if not should_inline(finding):
            continue
        rel = normalize_path(finding.get("filePath"))
        line = finding_line(finding)
        if not rel or line is None:
            continue
        ado_path = "/" + rel
        if ado_path not in changed:
            continue
        key = (ado_path, line, finding.get("ruleId"))
        if key in seen:
            continue
        seen.add(key)
        body = {
            "comments": [{"parentCommentId": 0, "content": inline_body(finding), "commentType": 1}],
            "status": 1,
            "threadContext": {
                "filePath": ado_path,
                "rightFileStart": {"line": line, "offset": 1},
                "rightFileEnd": {"line": line, "offset": 1},
            },
        }
        if _ado_request(ctx.threads_url(), ctx.token, method="POST", body=body, critical=False) is not None:
            posted += 1
    if posted:
        log.info("Posted %d inline PR thread(s).", posted)
    return posted


def _upsert_summary(ctx: _AdoContext, threads: list[dict], comment_body: str) -> None:
    thread_id, comment_id = _find_summary_thread(threads)
    if thread_id:
        result = _ado_request(
            ctx.thread_comment_url(thread_id, comment_id),
            ctx.token,
            method="PATCH",
            body={"content": comment_body, "commentType": 1},
        )
        if result is not None:
            log.info("PR summary comment updated (thread %s).", thread_id)
    else:
        result = _ado_request(
            ctx.threads_url(),
            ctx.token,
            method="POST",
            body={"comments": [{"parentCommentId": 0, "content": comment_body, "commentType": 1}], "status": 1},
        )
        if result is not None:
            log.info("PR summary comment posted.")


def post_or_update(
    api_url: str,
    api_key: str,
    pipeline_run_id: str,
    project_id: str | None = None,
) -> None:
    ctx = _AdoContext()
    if not ctx.pr_id:
        log.info("Not a PR build — skipping PR comment.")
        return
    if not ctx.complete:
        log.warning("Missing ADO environment variables for PR comment — skipping.")
        return

    threads_resp = _ado_request(ctx.threads_url(), ctx.token)
    if threads_resp is None:
        return
    threads = threads_resp.get("value", [])

    is_blocking = _fetch_blocking(api_url, api_key, pipeline_run_id)

    # Best-effort inline annotation; any failure falls back to the summary alone.
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
            # Capture the previous run's inline threads before posting so we can
            # remove them afterwards (always — not gated on the changed-paths
            # lookup — so stale threads are cleaned up even on a clean re-run).
            prior = _prior_inline_thread_comments(threads)
            changed = _changed_paths(ctx)
            inline_count = _post_inline_threads(ctx, findings, changed)
            _delete_inline_threads(ctx, prior)
        except Exception as e:  # noqa: BLE001 - decoration is best-effort
            log.warning("Inline PR annotation failed (%s); posting summary only.", e)

    _upsert_summary(ctx, threads, build_summary(is_blocking, total=total, inline_count=inline_count))


def _fetch_blocking(api_url: str, api_key: str, pipeline_run_id: str) -> bool:
    url = f"{api_url}/findings/blocking?pipelineRunId={pipeline_run_id}"
    req = urllib.request.Request(url, headers={"X-Api-Key": api_key})
    try:
        with urllib.request.urlopen(req) as resp:
            return bool(json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        log.warning("Could not fetch blocking status (%d) — assuming not blocking.", e.code)
        return False
