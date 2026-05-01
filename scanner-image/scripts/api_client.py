import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

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
    resp = s.post(url, json=payload, timeout=120, verify=True)
    if resp.status_code == 401:
        log.error("Authentication failed — check SECUREOBS_API_KEY.")
        import sys; sys.exit(1)
    if not resp.ok:
        log.error("API returned %s: %s", resp.status_code, resp.text[:200])
        import sys; sys.exit(2)
    return resp.json() if resp.content else {}


def get_blocking(api_url: str, api_key: str, pipeline_run_id: str) -> bool:
    url = f"{api_url}/findings/blocking?pipelineRunId={pipeline_run_id}"
    log.debug("GET %s", url)
    s = _session(api_key)
    resp = s.get(url, timeout=15, verify=True)
    if resp.status_code == 401:
        log.error("Authentication failed — check SECUREOBS_API_KEY.")
        import sys; sys.exit(1)
    if not resp.ok:
        log.error("Gate check returned %s: %s", resp.status_code, resp.text[:200])
        import sys; sys.exit(2)
    return bool(resp.json())
