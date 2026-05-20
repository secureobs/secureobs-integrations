import logging
import os
import sys
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

SCANNER_IMAGE_VERSION = os.environ.get("SECUREOBS_IMAGE_VERSION", "unknown")
_AUTH_FAILED_MSG = "Authentication failed — check SECUREOBS_API_KEY."

_RETRY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[502, 503, 504],
    allowed_methods=["GET", "POST"],
    raise_on_status=False,
)


def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"X-Api-Key": api_key, "Content-Type": "application/json"})
    adapter = HTTPAdapter(max_retries=_RETRY)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def post_findings(api_url: str, api_key: str, path: str, payload: list) -> dict:
    url = f"{api_url}/{path}"
    log.debug("POST %s (%d items)", url, len(payload))
    s = _session(api_key)
    enriched = [
        {**item, "scannerImageVersion": SCANNER_IMAGE_VERSION}
        if isinstance(item, dict) else item
        for item in payload
    ]
    resp = s.post(url, json=enriched, timeout=120, verify=True)
    if resp.status_code == 401:
        log.error(_AUTH_FAILED_MSG)
        sys.exit(1)
    if not resp.ok:
        log.error("API returned %s: %s", resp.status_code, resp.text)
        sys.exit(2)
    return resp.json() if resp.content else {}


def get_blocking(api_url: str, api_key: str, pipeline_run_id: str) -> bool:
    url = f"{api_url}/findings/blocking?pipelineRunId={pipeline_run_id}"
    log.debug("GET %s", url)
    s = _session(api_key)
    resp = s.get(url, timeout=15, verify=True)
    if resp.status_code == 401:
        log.error(_AUTH_FAILED_MSG)
        sys.exit(1)
    if not resp.ok:
        log.error("Gate check returned %s: %s", resp.status_code, resp.text[:200])
        sys.exit(2)
    return bool(resp.json())


def get_active_scanners(
    api_url: str, api_key: str, project_id: str
) -> list[dict[str, Any]] | None:
    """Fetch the scanners enabled for ``project_id`` from the SecureObs API.

    The response is the source of truth for which drivers should run on this
    pipeline invocation. Returning ``None`` signals the caller to fall back to
    the built-in defaults — we use that for transient network/server errors so
    a flaky control-plane never breaks the user's pipeline outright.

    Auth failures and a missing project, however, are NOT recoverable: the API
    key is wrong or the project ID is wrong, and silently scanning with the
    defaults would hide that bug. Those cases exit with code 1, matching the
    behaviour of every other endpoint in this client.
    """
    url = f"{api_url}/projects/{project_id}/scanners/active"
    log.debug("GET %s", url)
    s = _session(api_key)
    try:
        resp = s.get(url, timeout=15, verify=True)
    except requests.RequestException as e:
        log.warning("Could not reach %s (%s); will fall back to default scanners.", url, e)
        return None

    if resp.status_code == 401:
        log.error(_AUTH_FAILED_MSG)
        sys.exit(1)
    if resp.status_code == 404:
        log.error(
            "Project %s was not found in the tenant tied to this API key. "
            "Double-check --project-id and --tenant-id.",
            project_id,
        )
        sys.exit(1)
    if not resp.ok:
        log.warning(
            "Active-scanners endpoint returned %s; will fall back to defaults. Body: %s",
            resp.status_code,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except ValueError:
        log.warning("Active-scanners endpoint returned non-JSON; will fall back to defaults.")
        return None

    if not isinstance(data, list):
        log.warning(
            "Active-scanners endpoint returned %s instead of a list; will fall back to defaults.",
            type(data).__name__,
        )
        return None

    return data
