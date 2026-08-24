"""Security utilities — rate limiting, lockout, and response hardening.

Three concerns handled here so they don't scatter across routers:

  RateLimiter       — in-memory sliding-window counter keyed by arbitrary string
                      (IP address, username, etc.). Thread-safe. Resets on restart
                      — acceptable for a local admin tool where server access already
                      implies a degree of trust; the goal is stopping online
                      credential-guessing, not forensic audit.

  validate_queue_id — rejects any queue_id that isn't a safe alphanumeric slug,
                      preventing path-traversal attacks on spool operations.

  assert_within_root — resolves a Path and raises 403 if it escapes a root dir,
                        defence-in-depth after queue_id validation.

  SecurityHeadersMiddleware — adds OWASP-recommended response headers to every
                               reply without touching individual routers.
"""
from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from pathlib import Path

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window in-memory rate limiter.

    Args:
        max_attempts: maximum calls allowed within window_seconds.
        window_seconds: rolling window size in seconds.
        lockout_seconds: how long to block after threshold is exceeded
                         (defaults to window_seconds if None).
    """

    def __init__(
        self,
        max_attempts: int,
        window_seconds: int,
        lockout_seconds: int | None = None,
    ) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._lockout = lockout_seconds if lockout_seconds is not None else window_seconds
        self._log: dict[str, list[float]] = defaultdict(list)
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_limited(self, key: str) -> bool:
        """Return True and record the attempt if the caller is rate-limited.

        Side effect: records a timestamp even when not yet limited, so that
        the Nth+1 attempt sees the full window of prior calls.
        """
        now = time.monotonic()
        with self._lock:
            # Check hard lockout first (triggered when max was exceeded).
            if now < self._blocked_until.get(key, 0):
                return True

            cutoff = now - self._window
            history = [t for t in self._log[key] if t > cutoff]
            history.append(now)
            self._log[key] = history

            if len(history) > self._max:
                self._blocked_until[key] = now + self._lockout
                return True
            return False

    def clear(self, key: str) -> None:
        """Clear rate-limit state for a key (e.g. on successful auth)."""
        with self._lock:
            self._log.pop(key, None)
            self._blocked_until.pop(key, None)


# Shared limiters — imported by auth router.
# 10 attempts per 5 min per IP (catches slow credential spray).
ip_login_limiter = RateLimiter(max_attempts=10, window_seconds=300, lockout_seconds=300)
# 5 attempts per 10 min per username (protects individual accounts).
username_lockout = RateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=900)


# ---------------------------------------------------------------------------
# Queue-ID validation
# ---------------------------------------------------------------------------

_QUEUE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


def validate_queue_id(queue_id: str) -> None:
    """Raise HTTP 400 if queue_id contains path-traversal or shell-unsafe chars."""
    if not _QUEUE_ID_RE.match(queue_id):
        raise HTTPException(status_code=400, detail="invalid queue_id")


def assert_within_root(path: Path, root: Path) -> None:
    """Raise HTTP 403 if `path` resolves outside `root` (path-traversal guard)."""
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="access denied")


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

# Content-Security-Policy: 'unsafe-inline' is required because the dashboard
# uses inline <script> and <style> blocks throughout index.html. Restricting
# to 'self' for every other directive still prevents the worst-case attacks
# (data exfiltration, framing, MIME confusion). Refactoring the dashboard to
# use a nonce-based CSP is a worthwhile future hardening step.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self';"
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": _CSP,
    "Cache-Control": "no-store",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        # Remove headers that reveal implementation details.
        for h in ("server", "x-powered-by"):
            if h in response.headers:
                del response.headers[h]
        return response
