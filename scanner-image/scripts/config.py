import logging
import os
import sys

DEFAULT_API_URL = "https://api.secureobs.com/api"

log = logging.getLogger(__name__)


def setup_logging() -> None:
    level = logging.DEBUG if os.environ.get("SECUREOBS_DEBUG") == "1" else logging.INFO
    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if value is not None:
        # CI secret stores routinely append a trailing newline or space when a
        # key is pasted or piped in. An X-Api-Key carrying stray whitespace is
        # sent verbatim and rejected by the API as a 401 — or, for a newline,
        # rejected outright by urllib3's header validation. Strip so a correct
        # key that merely picked up surrounding whitespace still authenticates.
        value = value.strip()
    if not value:
        log.error("Required environment variable %s is not set.", name)
        sys.exit(1)
    return value


def get_api_url() -> str:
    return os.environ.get("SECUREOBS_API_URL", DEFAULT_API_URL).rstrip("/")
