"""Stateful JWT + RFC 6750 Bearer presentation."""
from __future__ import annotations

import time

from backend.api.tokens import decode_access_token, encode_access_token, session_key


def test_access_token_round_trip():
    token = encode_access_token(
        sub="7", username="alice", role="admin", jti="abc123", ttl_seconds=60,
    )
    claims = decode_access_token(token)
    assert claims is not None
    assert claims["sub"] == "7"
    assert claims["jti"] == "abc123"
    assert claims["roles"] == ["admin"]
    assert claims["token_use"] == "access"
    assert session_key(token) == "abc123"


def test_tampered_token_rejected():
    token = encode_access_token(
        sub="1", username="bob", role="viewer", jti="jti1", ttl_seconds=60,
    )
    parts = token.split(".")
    bad = parts[0] + "." + parts[1] + "." + ("A" * len(parts[2]))
    assert decode_access_token(bad) is None


def test_expired_token_rejected():
    token = encode_access_token(
        sub="1", username="bob", role="viewer", jti="jti1", ttl_seconds=-1,
    )
    time.sleep(0.01)
    assert decode_access_token(token) is None
