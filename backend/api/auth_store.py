"""User accounts + sessions — RBAC (Admin/Analyst/Viewer) for the dashboard.

SQLite, following workers/pipeline/correlation.py's established pattern exactly
(_DEFAULT_DB_PATH under data/ — already gitignored — _connect() with
mkdir(parents=True, exist_ok=True) + executescript(_SCHEMA)).

Password hashing: stdlib hashlib.pbkdf2_hmac + secrets — no new dependency,
same "standalone" posture as VTAbuseIPDBIntelClient (workers/pipeline/intel.py)
using stdlib urllib instead of an SDK.

Sessions: stateful JWTs (RFC 7519). The compact token is what the client
presents; `sessions.token` stores the `jti` so logout and password reset
revoke immediately.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

from backend.paths import DATA_DIR

_DEFAULT_DB_PATH = DATA_DIR / "users.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
    created_at REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    external_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT 'Passkey',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    session_token TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_logins (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    purpose TEXT NOT NULL,
    expires_at REAL NOT NULL
);
"""
_PENDING_LOGIN_TTL_SECONDS = 5 * 60

_CONTENT_UNLOCK_SECONDS = 30 * 60
_CHALLENGE_TTL_SECONDS = 5 * 60

_PBKDF2_ITERATIONS = 600_000   # NIST SP 800-132 (2023) recommendation for PBKDF2-SHA256
_SESSION_TTL_SECONDS = 12 * 3600   # 12h — a local admin tool, not a public SaaS
_MAX_SESSIONS_PER_USER = 10        # cap concurrent sessions; oldest evicted on overflow
ROLES = ("admin", "analyst", "viewer")

# Dummy credential for constant-time comparison when username is not found.
# Pre-computed once at import to avoid timing oracle that reveals valid usernames.
_DUMMY_SALT = secrets.token_bytes(16)
_DUMMY_HASH = hashlib.pbkdf2_hmac(
    "sha256", b"__dummy__", _DUMMY_SALT, _PBKDF2_ITERATIONS
).hex()


class User:
    def __init__(self, id: int, username: str, role: str, disabled: bool = False):
        self.id = id
        self.username = username
        self.role = role
        self.disabled = disabled

    def has_role(self, *roles: str) -> bool:
        return self.role in roles


class AuthStore:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH

    def _connect(self):
        from backend.db import connect as db_connect, is_postgres
        conn = db_connect(self.db_path, schema=_SCHEMA)
        if is_postgres():
            return conn
        cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if "content_unlocked_until" not in cols:
            conn.execute(
                "ALTER TABLE sessions ADD COLUMN content_unlocked_until REAL NOT NULL DEFAULT 0"
            )
        if "content_unlocked_thread" not in cols:
            conn.execute(
                "ALTER TABLE sessions ADD COLUMN content_unlocked_thread TEXT NOT NULL DEFAULT ''"
            )
        user_cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "email" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        if "display_name" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        if "external_id" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN external_id TEXT NOT NULL DEFAULT ''")
        conn.commit()
        return conn

    # --- passwords ---------------------------------------------------------
    @staticmethod
    def _validate_password_complexity(pw: str) -> None:
        """Raise ValueError describing the first failing complexity rule."""
        if len(pw) < 8:
            raise ValueError("Password must be at least 8 characters.")
        if not re.search(r"[A-Z]", pw):
            raise ValueError("Password must contain at least one uppercase letter (A–Z).")
        if not re.search(r"[a-z]", pw):
            raise ValueError("Password must contain at least one lowercase letter (a–z).")
        if not re.search(r"\d", pw):
            raise ValueError("Password must contain at least one number (0–9).")
        if not re.search(r"[^A-Za-z0-9]", pw):
            raise ValueError("Password must contain at least one special character (!@#$%^&* …).")

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                   _PBKDF2_ITERATIONS).hex()

    # --- users ---------------------------------------------------------------
    def user_count(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        finally:
            conn.close()

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        *,
        email: str = "",
        display_name: str = "",
        external_id: str = "",
    ) -> User:
        if role not in ROLES:
            raise ValueError(f"invalid role: {role!r}")
        self._validate_password_complexity(password)
        salt = secrets.token_bytes(16)
        password_hash = self._hash_password(password, salt)
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at, "
                "email, display_name, external_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    username, password_hash, salt.hex(), role, time.time(),
                    (email or "").strip(), (display_name or "").strip(),
                    (external_id or "").strip(),
                ),
            )
            conn.commit()
            return User(id=cur.lastrowid, username=username, role=role)
        finally:
            conn.close()

    @staticmethod
    def _user_row(row) -> dict:
        return {
            "id": row[0],
            "username": row[1],
            "role": row[2],
            "disabled": bool(row[3]),
            "created_at": row[4],
            "email": row[5] or "",
            "display_name": row[6] or "",
            "external_id": row[7] or "",
        }

    def list_users(self) -> list:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, username, role, disabled, created_at, email, display_name, external_id "
                "FROM users ORDER BY username"
            ).fetchall()
            return [self._user_row(r) for r in rows]
        finally:
            conn.close()

    def get_user_row(self, user_id: int) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, username, role, disabled, created_at, email, display_name, external_id "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            return self._user_row(row) if row else None
        finally:
            conn.close()

    def get_user_by_username(self, username: str) -> Optional[User]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, username, role, disabled FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return None
            return User(id=row[0], username=row[1], role=row[2], disabled=bool(row[3]))
        finally:
            conn.close()

    def update_user_profile(self, user_id: int, **fields) -> None:
        allowed = {
            "username": "username",
            "role": "role",
            "email": "email",
            "display_name": "display_name",
            "external_id": "external_id",
            "disabled": "disabled",
        }
        sets: list[str] = []
        values: list = []
        for key, column in allowed.items():
            if key not in fields:
                continue
            value = fields[key]
            if key == "role" and value not in ROLES:
                raise ValueError(f"invalid role: {value!r}")
            if key == "disabled":
                value = int(bool(value))
            sets.append(f"{column} = ?")
            values.append(value)
        if not sets:
            return
        values.append(user_id)
        conn = self._connect()
        try:
            conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", values)
            conn.commit()
        finally:
            conn.close()

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        conn = self._connect()
        try:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
            conn.commit()
        finally:
            conn.close()

    def set_password(self, user_id: int, new_password: str, *, keep_token: str | None = None) -> None:
        """Rotate a user's password. Admin resets revoke every session; self-service
        keeps the current session (identified by ``keep_token``) and drops the rest."""
        self._validate_password_complexity(new_password)
        salt = secrets.token_bytes(16)
        password_hash = self._hash_password(new_password, salt)
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                (password_hash, salt.hex(), user_id),
            )
            if cur.rowcount == 0:
                raise ValueError(f"user id {user_id} not found")
            conn.commit()
        finally:
            conn.close()
        if keep_token:
            self.delete_other_sessions_for_user(user_id, keep_token)
        else:
            self.delete_all_sessions_for_user(user_id)

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, username, role, disabled FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if row is None:
                return None
            return User(id=row[0], username=row[1], role=row[2], disabled=bool(row[3]))
        finally:
            conn.close()

    def delete_user(self, user_id: int) -> None:
        conn = self._connect()
        try:
            tokens = [r[0] for r in conn.execute(
                "SELECT token FROM sessions WHERE user_id = ?", (user_id,)).fetchall()]
            if tokens:
                conn.execute(
                    f"DELETE FROM webauthn_challenges WHERE session_token IN ({','.join('?' * len(tokens))})",
                    tokens,
                )
            conn.execute("DELETE FROM passkeys WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM pending_logins WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()

    # --- authentication -------------------------------------------------------
    def verify_password(self, username: str, password: str) -> Optional[User]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, username, password_hash, salt, role, disabled FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                # Perform a dummy hash to equalise timing for unknown usernames,
                # preventing a timing side-channel that reveals valid usernames.
                secrets.compare_digest(
                    self._hash_password(password, _DUMMY_SALT), _DUMMY_HASH
                )
                return None
            user_id, uname, password_hash, salt_hex, role, disabled = row
            if disabled:
                secrets.compare_digest(
                    self._hash_password(password, _DUMMY_SALT), _DUMMY_HASH
                )
                return None
            candidate = self._hash_password(password, bytes.fromhex(salt_hex))
            if not secrets.compare_digest(candidate, password_hash):
                return None
            return User(id=user_id, username=uname, role=role)
        finally:
            conn.close()

    # --- sessions ---------------------------------------------------------------
    def create_session(self, user_id: int) -> str:
        from .tokens import encode_access_token, SESSION_TTL_SECONDS

        user = self.get_user_by_id(user_id)
        if user is None or user.disabled:
            raise ValueError("cannot create session for unknown or disabled user")
        jti = secrets.token_urlsafe(32)
        now = time.time()
        conn = self._connect()
        try:
            # Prune expired sessions globally (housekeeping — prevents DB bloat).
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            conn.execute("DELETE FROM pending_logins WHERE expires_at <= ?", (now,))
            # Enforce per-user session cap: evict oldest sessions over the limit.
            existing = conn.execute(
                "SELECT token FROM sessions WHERE user_id = ? ORDER BY created_at ASC",
                (user_id,),
            ).fetchall()
            overflow = len(existing) - (_MAX_SESSIONS_PER_USER - 1)
            if overflow > 0:
                for (old_token,) in existing[:overflow]:
                    conn.execute("DELETE FROM sessions WHERE token = ?", (old_token,))
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (jti, user_id, now, now + SESSION_TTL_SECONDS),
            )
            conn.commit()
        finally:
            conn.close()
        return encode_access_token(
            sub=str(user.id), username=user.username, role=user.role, jti=jti,
            ttl_seconds=SESSION_TTL_SECONDS,
        )

    def resolve_session(self, token: str) -> Optional[User]:
        if not token:
            return None
        from .tokens import decode_access_token, session_key

        claims = decode_access_token(token)
        jti = session_key(token)
        if claims is None and token.count(".") == 2:
            return None
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT u.id, u.username, u.role, u.disabled, s.expires_at "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
                (jti,),
            ).fetchone()
            if row is None:
                return None
            user_id, username, role, disabled, expires_at = row
            if disabled or time.time() > expires_at:
                return None
            if claims and str(claims.get("sub")) != str(user_id):
                return None
            return User(id=user_id, username=username, role=role)
        finally:
            conn.close()

    def delete_session(self, token: str) -> None:
        from .tokens import session_key

        jti = session_key(token)
        conn = self._connect()
        try:
            conn.execute("DELETE FROM webauthn_challenges WHERE session_token = ?", (jti,))
            conn.execute("DELETE FROM webauthn_challenges WHERE session_token = ?", (token,))
            conn.execute("DELETE FROM sessions WHERE token = ?", (jti,))
            conn.commit()
        finally:
            conn.close()

    def create_pending_login(self, token: str, user_id: int, purpose: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM pending_logins WHERE expires_at <= ?", (time.time(),))
            conn.execute("DELETE FROM pending_logins WHERE token = ?", (token,))
            conn.execute(
                "INSERT INTO pending_logins (token, user_id, purpose, expires_at) VALUES (?, ?, ?, ?)",
                (token, user_id, purpose, time.time() + _PENDING_LOGIN_TTL_SECONDS),
            )
            conn.commit()
        finally:
            conn.close()

    def get_pending_login(self, token: str) -> Optional[dict]:
        if not token:
            return None
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT token, user_id, purpose, expires_at FROM pending_logins WHERE token = ?",
                (token,),
            ).fetchone()
            if row is None or time.time() > row[3]:
                return None
            return {"token": row[0], "user_id": row[1], "purpose": row[2]}
        finally:
            conn.close()

    def delete_pending_login(self, token: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM webauthn_challenges WHERE session_token = ?", (token,))
            conn.execute("DELETE FROM pending_logins WHERE token = ?", (token,))
            conn.commit()
        finally:
            conn.close()

    def delete_all_sessions_for_user(self, user_id: int) -> None:
        conn = self._connect()
        try:
            tokens = [r[0] for r in conn.execute(
                "SELECT token FROM sessions WHERE user_id = ?", (user_id,)).fetchall()]
            if tokens:
                conn.execute(
                    f"DELETE FROM webauthn_challenges WHERE session_token IN ({','.join('?' * len(tokens))})",
                    tokens,
                )
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()

    def delete_other_sessions_for_user(self, user_id: int, keep_token: str) -> None:
        """Revoke every session except the one matching ``keep_token`` (JWT or jti)."""
        from .tokens import session_key

        keep = session_key(keep_token) if keep_token else ""
        conn = self._connect()
        try:
            tokens = [r[0] for r in conn.execute(
                "SELECT token FROM sessions WHERE user_id = ?", (user_id,)).fetchall()]
            drop = [t for t in tokens if t != keep and t != (keep_token or "")]
            if drop:
                conn.execute(
                    f"DELETE FROM webauthn_challenges WHERE session_token IN ({','.join('?' * len(drop))})",
                    drop,
                )
                conn.execute(
                    f"DELETE FROM sessions WHERE user_id = ? AND token IN ({','.join('?' * len(drop))})",
                    [user_id, *drop],
                )
            conn.commit()
        finally:
            conn.close()

    # --- passkeys / content unlock ------------------------------------------
    def list_passkeys(self, user_id: int) -> list:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, name, created_at FROM passkeys WHERE user_id = ? ORDER BY created_at",
                (user_id,),
            ).fetchall()
            return [{"id": r[0], "name": r[1], "created_at": r[2]} for r in rows]
        finally:
            conn.close()

    def passkey_count(self, user_id: int) -> int:
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM passkeys WHERE user_id = ?", (user_id,)
            ).fetchone()[0]
        finally:
            conn.close()

    def add_passkey(self, user_id: int, credential_id: str, public_key: str,
                    sign_count: int, name: str = "Passkey") -> int:
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, name, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, credential_id, public_key, int(sign_count), name or "Passkey", time.time()),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()

    def get_passkey_by_credential_id(self, credential_id: str) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id, user_id, credential_id, public_key, sign_count, name "
                "FROM passkeys WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "id": row[0], "user_id": row[1], "credential_id": row[2],
                "public_key": row[3], "sign_count": row[4], "name": row[5],
            }
        finally:
            conn.close()

    def list_passkey_credential_ids(self, user_id: int) -> list[str]:
        conn = self._connect()
        try:
            return [r[0] for r in conn.execute(
                "SELECT credential_id FROM passkeys WHERE user_id = ?", (user_id,)
            ).fetchall()]
        finally:
            conn.close()

    def update_passkey_sign_count(self, passkey_id: int, sign_count: int) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE passkeys SET sign_count = ? WHERE id = ?",
                (int(sign_count), passkey_id),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_passkey(self, user_id: int, passkey_id: int) -> bool:
        conn = self._connect()
        try:
            cur = conn.execute(
                "DELETE FROM passkeys WHERE id = ? AND user_id = ?",
                (passkey_id, user_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def save_challenge(self, session_token: str, challenge: str, purpose: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM webauthn_challenges WHERE expires_at <= ?", (time.time(),))
            conn.execute(
                "DELETE FROM webauthn_challenges WHERE session_token = ?",
                (session_token,),
            )
            conn.execute(
                "INSERT INTO webauthn_challenges "
                "(session_token, challenge, purpose, expires_at) VALUES (?, ?, ?, ?)",
                (session_token, challenge, purpose, time.time() + _CHALLENGE_TTL_SECONDS),
            )
            conn.commit()
        finally:
            conn.close()

    def pop_challenge(self, session_token: str, purpose: str) -> Optional[str]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT challenge, purpose, expires_at FROM webauthn_challenges "
                "WHERE session_token = ?",
                (session_token,),
            ).fetchone()
            conn.execute("DELETE FROM webauthn_challenges WHERE session_token = ?", (session_token,))
            conn.commit()
            if row is None or row[1] != purpose or time.time() > row[2]:
                return None
            return row[0]
        finally:
            conn.close()

    def unlock_content(self, session_token: str, thread_key: str = "*") -> None:
        from .tokens import session_key

        until = time.time() + _CONTENT_UNLOCK_SECONDS
        jti = session_key(session_token)
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE sessions SET content_unlocked_until = ?, content_unlocked_thread = ? "
                "WHERE token = ?",
                (until, thread_key or "*", jti),
            )
            conn.commit()
        finally:
            conn.close()

    def lock_content(self, session_token: str) -> None:
        from .tokens import session_key

        jti = session_key(session_token)
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE sessions SET content_unlocked_until = 0, content_unlocked_thread = '' "
                "WHERE token = ?",
                (jti,),
            )
            conn.commit()
        finally:
            conn.close()

    def unlocked_thread(self, session_token: str) -> str:
        from .tokens import session_key

        jti = session_key(session_token)
        if not session_token or not self.is_content_unlocked(session_token):
            return ""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT content_unlocked_thread FROM sessions WHERE token = ?",
                (jti,),
            ).fetchone()
            return str(row[0] or "").strip() if row else ""
        finally:
            conn.close()

    def is_content_unlocked(self, session_token: str, thread_key: str = "",
                            queue_id: str = "") -> bool:
        from .tokens import session_key

        if not session_token:
            return False
        jti = session_key(session_token)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT content_unlocked_until, expires_at, content_unlocked_thread "
                "FROM sessions WHERE token = ?",
                (jti,),
            ).fetchone()
            if row is None:
                return False
            now = time.time()
            if now > row[1] or now > float(row[0] or 0):
                return False
            stored = (row[2] or "").strip()
            if not stored:
                return False
            if stored == "*":
                return True
            if not thread_key and not queue_id:
                return True
            if thread_key and stored == thread_key:
                return True
            if queue_id:
                try:
                    from backend.api.feed_builder import candidate_unlock_keys
                    if stored in candidate_unlock_keys(queue_id):
                        return True
                except Exception:
                    pass
            return False
        finally:
            conn.close()


def get_default_store() -> AuthStore:
    return AuthStore()
