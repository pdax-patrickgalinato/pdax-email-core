"""Stateful JWT access tokens (RFC 7519 / RFC 9068 profile, RFC 6750 Bearer).

The compact JWT is what the client presents (cookie or Authorization header).
The `jti` claim is the primary key in `sessions`, so logout and password
reset remain instant revocation — the signature alone is not enough.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional

from backend.config import get_settings

ALGORITHM = "HS256"
TOKEN_TYPE = "at+jwt"
AUDIENCE = "segs-api"
SESSION_TTL_SECONDS = 12 * 3600


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def jwt_secret() -> bytes:
    settings = get_settings()
    secret = (settings.jwt_secret or "").encode("utf-8")
    if secret:
        return secret
    # Stable fallback so pytest and first-boot still issue verifiable tokens.
    return hashlib.sha256(b"segs-dev-jwt-hs256").digest()


def jwt_issuer() -> str:
    settings = get_settings()
    custom = (settings.jwt_issuer or "").strip()
    if custom:
        return custom
    origin = (settings.public_origin or "").strip().rstrip("/")
    return origin or "segs"


def encode_access_token(
    *,
    sub: str,
    username: str,
    role: str,
    jti: str,
    ttl_seconds: int = SESSION_TTL_SECONDS,
) -> str:
    now = int(time.time())
    header = {"alg": ALGORITHM, "typ": TOKEN_TYPE}
    payload = {
        "iss": jwt_issuer(),
        "sub": str(sub),
        "aud": [AUDIENCE],
        "exp": now + int(ttl_seconds),
        "iat": now,
        "nbf": now,
        "jti": jti,
        "token_use": "access",
        "username": username,
        "roles": [role],
    }
    signing_input = (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':'), sort_keys=True).encode())}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode())}"
    ).encode("ascii")
    sig = hmac.new(jwt_secret(), signing_input, hashlib.sha256).digest()
    return signing_input.decode("ascii") + "." + _b64url_encode(sig)


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    """Return claims if the JWT is well-formed, signed, and unexpired."""
    if not token or token.count(".") != 2:
        return None
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        expected = hmac.new(jwt_secret(), signing_input, hashlib.sha256).digest()
        presented = _b64url_decode(s_b64)
        if not hmac.compare_digest(expected, presented):
            return None
        header = json.loads(_b64url_decode(h_b64))
        if header.get("alg") != ALGORITHM:
            return None
        claims = json.loads(_b64url_decode(p_b64))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    now = int(time.time())
    try:
        if int(claims["exp"]) < now:
            return None
        if int(claims.get("nbf") or 0) > now:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    if not isinstance(aud, list) or AUDIENCE not in aud:
        return None
    if claims.get("iss") != jwt_issuer():
        return None
    if not claims.get("jti") or not claims.get("sub"):
        return None
    return claims


def session_key(presented: str) -> str:
    """Map a presented credential to the sessions.token primary key (jti)."""
    claims = decode_access_token(presented)
    if claims:
        return str(claims["jti"])
    return presented or ""
