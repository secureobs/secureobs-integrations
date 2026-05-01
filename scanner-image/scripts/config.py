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
    if not value:
        log.error("Required environment variable %s is not set.", name)
        sys.exit(1)
    return value


def get_api_url() -> str:
    return os.environ.get("SECUREOBS_API_URL", DEFAULT_API_URL).rstrip("/")
