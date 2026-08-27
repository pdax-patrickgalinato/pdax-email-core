"""Security utilities — rate limiting, lockout, request size limits, and response hardening.

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

import os
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

# Limiters for expensive pipeline-invoking endpoints.
# Keyed by username to prevent a compromised account from flooding the LLM API
# or exhausting VT/AbuseIPDB rate limits.
analyze_limiter = RateLimiter(max_attempts=20, window_seconds=60)   # 20 EML analyses/user/min
reevaluate_limiter = RateLimiter(max_attempts=10, window_seconds=60)  # 10 re-evals/user/min
admin_write_limiter = RateLimiter(max_attempts=5, window_seconds=60)  # enforcement/policy writes


# ---------------------------------------------------------------------------
# Request body size limit
# ---------------------------------------------------------------------------

# 16 MB global cap — large enough to allow EML uploads (which have their own
# 15 MB check), small enough to stop memory-exhaustion from arbitrary POST bodies.
_BODY_SIZE_LIMIT = int(os.getenv("SEG_MAX_BODY_BYTES", str(16 * 1024 * 1024)))


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured limit.

    Checks the Content-Length header if present; does not buffer or re-read
    the body, so chunked-encoding requests without a Content-Length bypass
    this check — in-route limits (EML 15 MB check) handle those.  For a
    local admin tool, Content-Length checking stops accidental or scripted
    oversized requests without introducing streaming complexity.
    """

    def __init__(self, app, max_bytes: int = _BODY_SIZE_LIMIT) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_bytes:
                    return Response(
                        content='{"detail":"request too large"}',
                        status_code=413,
                        media_type="application/json",
                    )
            except ValueError:
                pass  # malformed Content-Length — let the framework handle it
        return await call_next(request)


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

_COOKIE_SECURE = os.getenv("SEG_COOKIE_SECURE", "").strip() in ("1", "true", "yes")

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": _CSP,
    "Cache-Control": "no-store",
    # Cross-origin isolation headers — mitigate Spectre-class side-channel attacks
    # and prevent cross-origin data leaks via SharedArrayBuffer or process reuse.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
}

# Strict-Transport-Security: only meaningful over HTTPS — suppress on plain HTTP
# so browsers don't mark the site as HSTS-preloaded while it's still on HTTP.
if _COOKIE_SECURE:
    _SECURITY_HEADERS["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


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


# ---------------------------------------------------------------------------
# SSO middleware — JumpCloud SSO readiness hook
# ---------------------------------------------------------------------------

_SSO_PROVIDER = os.getenv("SEG_SSO_PROVIDER", "").strip().lower()

# Paths that must remain reachable without SSO:
#   /api/health       — ALB health check (runs before any session exists)
#   /api/auth/*       — login, setup wizard, logout (bootstrapping)
_SSO_BYPASS_PREFIXES = ("/api/health", "/api/auth/")


class SSOMiddleware(BaseHTTPMiddleware):
    """JumpCloud SSO gate.

    Controlled by SEG_SSO_PROVIDER (empty = disabled):

      alb_oidc  — Trust the x-amzn-oidc-identity header injected by the AWS
                  ALB OIDC authenticator after it validates the JumpCloud token.
                  The ALB does the heavy lifting; this middleware just rejects
                  any request that bypassed the ALB (i.e. the header is absent).

    When SEG_SSO_PROVIDER is empty or unset, this middleware is a no-op and all
    traffic falls through to the app's own session-cookie auth.

    To activate: set SEG_SSO_PROVIDER=alb_oidc in Secrets Manager + redeploy,
    and configure the ALB OIDC listener rule as described in docs/JUMPCLOUD_SSO.md.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if not _SSO_PROVIDER:
            return await call_next(request)

        path = request.url.path
        for prefix in _SSO_BYPASS_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)

        if _SSO_PROVIDER == "alb_oidc":
            if not request.headers.get("x-amzn-oidc-identity"):
                return Response(
                    content="Access denied — authenticate via the organization SSO portal.",
                    status_code=401,
                    headers={"WWW-Authenticate": 'Bearer realm="SEGS"'},
                )

        return await call_next(request)
