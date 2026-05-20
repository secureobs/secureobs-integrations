import base64
import json
import logging
import os
import sys
import urllib.error
import urllib.request

from .common import MARKER, build_comment

log = logging.getLogger(__name__)


def _auth_header(token: str) -> str:
    encoded = base64.b64encode(f":{token}".encode()).decode()
    return f"Basic {encoded}"


def _ado_request(url: str, token: str, method: str = "GET", body: dict | None = None):
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
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:300]
        if e.code == 403:
            log.warning("PR comment: 403 Forbidden — tenant may not support PR comments on this tier. Skipping.")
            return None
        log.exception("ADO API %s %s returned %d: %s", method, url, e.code, body_text)
        sys.exit(2)


def post_or_update(
    api_url: str,
    api_key: str,
    pipeline_run_id: str,
) -> None:
    pr_id = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID")
    if not pr_id:
        log.info("Not a PR build — skipping PR comment.")
        return

    collection_uri = os.environ.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "").rstrip("/")
    project = os.environ.get("SYSTEM_TEAMPROJECT", "")
    repo_id = os.environ.get("BUILD_REPOSITORY_ID", "")
    token = os.environ.get("SYSTEM_ACCESSTOKEN", "")

    if not all([collection_uri, project, repo_id, token]):
        log.warning("Missing ADO environment variables for PR comment — skipping.")
        return

    is_blocking = _fetch_blocking(api_url, api_key, pipeline_run_id)
    comment_body = build_comment(is_blocking)

    threads_url = (
        f"{collection_uri}/{project}/_apis/git/repositories/{repo_id}"
        f"/pullRequests/{pr_id}/threads?api-version=7.1-preview.1"
    )

    threads_resp = _ado_request(threads_url, token)
    if threads_resp is None:
        return

    existing_thread_id = None
    existing_comment_id = None
    for thread in threads_resp.get("value", []):
        for comment in thread.get("comments", []):
            if MARKER in (comment.get("content") or ""):
                existing_thread_id = thread["id"]
                existing_comment_id = comment["id"]
                break
        if existing_thread_id:
            break

    if existing_thread_id:
        patch_url = (
            f"{collection_uri}/{project}/_apis/git/repositories/{repo_id}"
            f"/pullRequests/{pr_id}/threads/{existing_thread_id}"
            f"/comments/{existing_comment_id}?api-version=7.1-preview.1"
        )
        result = _ado_request(patch_url, token, method="PATCH", body={"content": comment_body, "commentType": 1})
        if result is not None:
            log.info("PR comment updated (thread %s).", existing_thread_id)
    else:
        result = _ado_request(
            threads_url,
            token,
            method="POST",
            body={
                "comments": [{"parentCommentId": 0, "content": comment_body, "commentType": 1}],
                "status": 1,
            },
        )
        if result is not None:
            log.info("PR comment posted.")


def _fetch_blocking(api_url: str, api_key: str, pipeline_run_id: str) -> bool:
    url = f"{api_url}/findings/blocking?pipelineRunId={pipeline_run_id}"
    req = urllib.request.Request(url, headers={"X-Api-Key": api_key})
    try:
        with urllib.request.urlopen(req) as resp:
            return bool(json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        log.warning("Could not fetch blocking status (%d) — assuming not blocking.", e.code)
        return False
