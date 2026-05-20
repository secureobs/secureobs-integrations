import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request

from .common import MARKER, build_comment

log = logging.getLogger(__name__)


def _gh_request(url: str, token: str, method: str = "GET", body: dict | None = None):
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
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:300]
        if e.code == 403:
            log.warning("PR comment: 403 Forbidden — tenant may not support PR comments on this tier. Skipping.")
            return None
        log.exception("GitHub API %s %s returned %d: %s", method, url, e.code, body_text)
        sys.exit(2)


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


def post_or_update(
    api_url: str,
    api_key: str,
    pipeline_run_id: str,
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
    comment_body = build_comment(is_blocking)

    comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    existing_comments = _gh_request(comments_url, token) or []

    existing_comment_id = None
    for c in existing_comments:
        if MARKER in (c.get("body") or ""):
            existing_comment_id = c["id"]
            break

    if existing_comment_id:
        patch_url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_comment_id}"
        result = _gh_request(patch_url, token, method="PATCH", body={"body": comment_body})
        if result is not None:
            log.info("PR comment updated (comment %s).", existing_comment_id)
    else:
        result = _gh_request(comments_url, token, method="POST", body={"body": comment_body})
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
