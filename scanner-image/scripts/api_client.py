import logging
import json
import os
import sys
from typing import Any


import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

SCANNER_IMAGE_VERSION = os.environ.get("SECUREOBS_IMAGE_VERSION", "unknown")
_AUTH_FAILED_MSG = "Authentication failed — check SECUREOBS_API_KEY."
_LOG_GET = "GET %s"
_MAX_FINDINGS_PER_BATCH = 1_000
_MAX_FINDINGS_BATCH_BYTES = 6 * 1024 * 1024

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


class ApiError(Exception):
    """A SecureObs API call failed. ``transient`` marks network/5xx failures."""

    def __init__(self, status: int | None, message: str, *, code: str | None = None,
                 transient: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.transient = transient


class ApiAuthError(ApiError):
    """401 — the API key is missing, revoked, expired or malformed."""


def _error_from_response(resp: requests.Response) -> ApiError:
    code = None
    try:
        body = resp.json()
        if isinstance(body, dict):
            code = body.get("error") if isinstance(body.get("error"), str) else None
            detail = body.get("message") or body.get("detail") or code or ""
        else:
            detail = ""
    except ValueError:
        detail = (resp.text or "")[:300]
    message = f"API returned {resp.status_code}" + (f": {str(detail)[:300]}" if detail else "")
    if resp.status_code == 401:
        return ApiAuthError(401, _AUTH_FAILED_MSG, code=code)
    return ApiError(resp.status_code, message, code=code, transient=resp.status_code >= 500)


def post_findings_checked(api_url: str, api_key: str, path: str, payload: list) -> dict:
    """Upload findings in bounded batches; raise ``ApiError`` on any failure.

    Batches are idempotent on the server (fingerprint deduplication), so a run
    interrupted after some batches can simply be retried.
    """
    url = f"{api_url}/{path}"
    log.debug("POST %s (%d items)", url, len(payload))
    s = _session(api_key)
    enriched = [
        {**item, "scannerImageVersion": SCANNER_IMAGE_VERSION}
        if isinstance(item, dict) else item
        for item in payload
    ]
    ingested = 0
    deduplicated: int | None = None   # only when the API reports it; never assumed
    for batch in _finding_batches(enriched):
        try:
            resp = s.post(url, json=batch, timeout=120, verify=True)
        except requests.RequestException as exc:
            raise ApiError(None, f"network error contacting SecureObs: {type(exc).__name__}",
                           transient=True) from exc
        if not resp.ok:
            raise _error_from_response(resp)
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            body = {}
        ingested += int(body.get("ingested", len(batch)))
        if isinstance(body, dict) and "deduplicated" in body:
            deduplicated = (deduplicated or 0) + int(body["deduplicated"])
    return {"ingested": ingested, "deduplicated": deduplicated}


def post_findings(api_url: str, api_key: str, path: str, payload: list) -> dict:
    try:
        return post_findings_checked(api_url, api_key, path, payload)
    except ApiAuthError:
        log.error(_AUTH_FAILED_MSG)
        sys.exit(1)
    except ApiError as exc:
        log.error("%s", exc)
        sys.exit(2)


def _finding_batches(items: list) -> list[list]:
    """Bound finding requests by both API item count and serialized payload size."""
    batches: list[list] = []
    current: list = []
    current_bytes = 2  # JSON array brackets
    for item in items:
        item_bytes = len(json.dumps(item, separators=(",", ":")).encode("utf-8"))
        separator_bytes = 1 if current else 0
        if current and (
            len(current) >= _MAX_FINDINGS_PER_BATCH or
            current_bytes + separator_bytes + item_bytes > _MAX_FINDINGS_BATCH_BYTES
        ):
            batches.append(current)
            current = []
            current_bytes = 2
            separator_bytes = 0
        current.append(item)
        current_bytes += separator_bytes + item_bytes
    if current:
        batches.append(current)
    return batches


def get_blocking(api_url: str, api_key: str, pipeline_run_id: str) -> bool:
    url = f"{api_url}/findings/blocking?pipelineRunId={pipeline_run_id}"
    log.debug(_LOG_GET, url)
    s = _session(api_key)
    resp = s.get(url, timeout=15, verify=True)
    if resp.status_code == 401:
        log.error(_AUTH_FAILED_MSG)
        sys.exit(1)
    if not resp.ok:
        log.error("Gate check returned %s: %s", resp.status_code, resp.text[:200])
        sys.exit(2)
    return bool(resp.json())


def get_pr_findings(
    api_url: str, api_key: str, project_id: str, pipeline_run_id: str
) -> list[dict[str, Any]] | None:
    """Fetch the slim, PR-safe finding list for a pipeline run so the caller can
    place inline comments on the right file/line.

    Returns ``None`` on any failure. PR commenting is best-effort — a flaky fetch
    must never break the pipeline; the caller falls back to a summary-only
    comment when this returns ``None``.
    """
    url = f"{api_url}/findings/by-run?projectId={project_id}&pipelineRunId={pipeline_run_id}"
    log.debug(_LOG_GET, url)
    s = _session(api_key)
    try:
        resp = s.get(url, timeout=15, verify=True)
    except requests.RequestException as e:
        log.warning("Could not fetch PR findings (%s); skipping inline comments.", e)
        return None

    if not resp.ok:
        log.warning(
            "PR findings endpoint returned %s; skipping inline comments. Body: %s",
            resp.status_code,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except ValueError:
        log.warning("PR findings endpoint returned non-JSON; skipping inline comments.")
        return None

    return data if isinstance(data, list) else None


def post_infrastructure_analysis(
    api_url: str, api_key: str, payload: dict
) -> tuple[bool, Any]:
    """POST an infrastructure analysis payload to the SecureObs API.

    Unlike ``post_findings``, a failure here does NOT call ``sys.exit`` — the
    calling scanner must continue regardless.  The payload is expected to be a
    dict produced by ``infrastructure.terraform_plan``.

    Returns
    -------
    (True, response_dict)  on success.
    (False, error_string)  on any failure.
    """
    url = f"{api_url}/infrastructure-analyses/terraform-plan"
    log.debug("POST %s", url)
    s = _session(api_key)
    try:
        resp = s.post(url, json=payload, timeout=120, verify=True)
    except requests.RequestException as exc:
        msg = f"Network error posting infrastructure analysis: {exc}"
        log.error(msg)
        return False, msg

    if resp.status_code == 401:
        log.error(_AUTH_FAILED_MSG)
        return False, _AUTH_FAILED_MSG

    if not resp.ok:
        msg = f"Infrastructure-analysis API returned {resp.status_code}: {resp.text[:200]}"
        log.error(msg)
        return False, msg

    try:
        body = resp.json() if resp.content else {}
    except ValueError:
        body = {}

    return True, body


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
    log.debug(_LOG_GET, url)
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


def post_scan_executions_checked(
    api_url: str, api_key: str, project_id: str, pipeline_run_id: str, executions: list[dict]
) -> None:
    """Report per-scanner execution outcomes; raise ``ApiError`` on failure."""
    url = f"{api_url}/scan-executions"
    payload = {
        "projectId": project_id,
        "pipelineRunId": pipeline_run_id,
        "scannerImageVersion": SCANNER_IMAGE_VERSION,
        "executions": executions,
    }
    try:
        resp = _session(api_key).post(url, json=payload, timeout=30, verify=True)
    except requests.RequestException as exc:
        raise ApiError(None, f"network error ({type(exc).__name__})", transient=True) from exc
    if resp.status_code == 404 and not _is_json_error(resp):
        raise ApiError(404, "this SecureObs API does not accept execution status yet",
                       code="endpoint_unavailable")
    if not resp.ok:
        raise _error_from_response(resp)


def post_scan_executions(
    api_url: str, api_key: str, project_id: str, pipeline_run_id: str, executions: list[dict]
) -> bool:
    """Best-effort wrapper: logs and returns False on failure.

    The server-side gate treats a missing report as "not completed", so a lost
    report can never turn a required-but-failed scanner into a pass.
    """
    if not executions:
        return True
    try:
        post_scan_executions_checked(api_url, api_key, project_id, pipeline_run_id, executions)
    except ApiError as exc:
        log.warning("Scanner execution status was not recorded: %s", exc)
        return False
    return True


def _is_json_error(resp: requests.Response) -> bool:
    try:
        body = resp.json()
    except ValueError:
        return False
    return isinstance(body, dict) and isinstance(body.get("error"), str)


def get_gate_decision(
    api_url: str, api_key: str, project_id: str, pipeline_run_id: str
) -> dict[str, Any] | None:
    """Structured, project-scoped gate decision.

    Returns ``None`` only when the API predates this endpoint (route not found),
    so the caller can fall back to the legacy boolean gate. Every other failure
    exits: 1 for auth/configuration problems, 2 for API/network errors — a gate
    that cannot be evaluated never passes.
    """
    url = f"{api_url}/projects/{project_id}/gate"
    log.debug(_LOG_GET, url)
    try:
        resp = _session(api_key).get(
            url, params={"pipelineRunId": pipeline_run_id}, timeout=30, verify=True)
    except requests.RequestException as exc:
        log.error("Gate check failed: network error (%s).", type(exc).__name__)
        sys.exit(2)
    if resp.status_code == 401:
        log.error(_AUTH_FAILED_MSG)
        sys.exit(1)
    if resp.status_code == 404:
        if _is_json_error(resp):
            log.error(
                "Project %s was not found in the tenant tied to this API key. "
                "Double-check --project-id and the key's project scope.", project_id)
            sys.exit(1)
        return None
    if not resp.ok:
        log.error("Gate check failed: %s", _error_from_response(resp))
        sys.exit(2)
    try:
        body = resp.json()
    except ValueError:
        log.error("Gate check returned a non-JSON response.")
        sys.exit(2)
    if not isinstance(body, dict) or "outcome" not in body:
        log.error("Gate check returned an unexpected response shape.")
        sys.exit(2)
    return body
