"""Shared HTTP timeout policy for native network tools.

Executable-backed tools use their own ceiling (``OPENCYBER_TOOL_TIMEOUT_S``)
with the MCP client owning cancellation. Native HTTP calls are different -- without an explicit timeout a
single unresponsive target can block a tool call forever, so every `requests`
call in this package resolves its deadline here.

`OPENCYBER_HTTP_TIMEOUT` sets the process default (seconds). A caller-supplied
value wins over the environment. Both are capped by `MAX_TIMEOUT_SECONDS`.
"""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
import os
import math
from typing import Any, Callable
from urllib.parse import urljoin

from .policy import enforce_url_scope
from .errors import OcError
from .limits import limit_for


DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 300.0
ENV_VAR = "OPENCYBER_HTTP_TIMEOUT"
MAX_RESPONSE_BYTES = int(limit_for("http.response_max_bytes").default)


def bounded_response(response: Any, **kwargs: Any) -> Any:
    """Bound decoded bodies before requests automatically drains redirects."""
    captured = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=65536):
            captured.extend(chunk[:MAX_RESPONSE_BYTES + 1 - len(captured)])
            if len(captured) > MAX_RESPONSE_BYTES:
                break
    finally:
        response.close()
    response._opencyber_body_truncated = len(captured) > MAX_RESPONSE_BYTES
    # requests' redirect machinery reads .content even with stream=True.
    # Supply only the bounded prefix so it cannot drain an oversized body.
    response._content = bytes(captured[:MAX_RESPONSE_BYTES])
    response._content_consumed = True
    return response


@contextmanager
def request_errors() -> Iterator[None]:
    """Translate requests failures at the HTTP boundary, including streamed reads."""
    import requests
    from urllib3.exceptions import ReadTimeoutError

    try:
        yield
    except requests.exceptions.Timeout as exc:
        raise OcError("timed_out", str(exc)) from exc
    except requests.exceptions.ConnectionError as exc:
        # iter_content wraps urllib3's read timeout in ConnectionError.
        code = "timed_out" if any(isinstance(arg, ReadTimeoutError) for arg in exc.args) else "connection_failed"
        raise OcError(code, str(exc)) from exc


def resolve_timeout(value: float | None = None) -> float:
    """Return a validated timeout in seconds.

    ``None`` means "use the environment or the default". Booleans, non-numeric
    values, zero, negatives, and values above the cap are rejected rather than
    silently clamped, so a typo cannot disable the deadline.
    """

    if value is None:
        raw = os.environ.get(ENV_VAR, "").strip()
        if not raw:
            return DEFAULT_TIMEOUT_SECONDS
        try:
            value = float(raw)
        except ValueError as exc:
            raise ValueError(f"{ENV_VAR} must be a number of seconds, got {raw!r}") from exc

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("timeout must be a number of seconds")

    resolved = float(value)
    if not math.isfinite(resolved) or resolved <= 0 or resolved > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g} seconds")
    return resolved


def redirect_scope_hooks(
    engagement_id: str | None, *, tool: str, follow_redirects: bool = True
) -> dict[str, list[Callable[..., Any]]]:
    """Check every redirect before requests sends the next target request.

    Requests dispatches response hooks before its redirect machinery, and copies
    the hooks onto every redirected request. Keeping that machinery also keeps
    its method rewriting, cookie handling, credential stripping and hop limit.
    An unfollowed Location is data and must not require authority to contact it.
    """
    if not follow_redirects:
        return {}

    def check(response: Any, **kwargs: Any) -> Any:
        if response.is_redirect:
            target = urljoin(response.url, response.headers["location"])
            try:
                enforce_url_scope(engagement_id, target, tool=tool)
            except Exception:
                response.close()
                raise
        return response

    return {"response": [check]}
