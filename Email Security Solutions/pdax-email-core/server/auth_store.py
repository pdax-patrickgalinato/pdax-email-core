"""User accounts + sessions — RBAC (Admin/Analyst/Viewer) for the dashboard.

SQLite, following app/pipeline/correlation.py's established pattern exactly
(_DEFAULT_DB_PATH under data/ — already gitignored — _connect() with
mkdir(parents=True, exist_ok=True) + executescript(_SCHEMA)).

Password hashing: stdlib hashlib.pbkdf2_hmac + secrets — no new dependency,
same "standalone" posture as VTAbuseIPDBIntelClient (app/pipeline/intel.py)
using stdlib urllib instead of an SDK.

Sessions: opaque server-side tokens in the `sessions` table, not a signed
stateless cookie — trivially revocable (delete the row), no signing library
needed. A session is just a row; "log out everywhere" for a user is one
DELETE.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "users.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
    created_at REAL NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""

_PBKDF2_ITERATIONS = 200_000
_SESSION_TTL_SECONDS = 12 * 3600   # 12h — a local admin tool, not a public SaaS
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

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.executescript(_SCHEMA)
        return conn

    # --- passwords ---------------------------------------------------------
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

    def create_user(self, username: str, password: str, role: str) -> User:
        if role not in ROLES:
            raise ValueError(f"invalid role: {role!r}")
        salt = secrets.token_bytes(16)
        password_hash = self._hash_password(password, salt)
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, salt.hex(), role, time.time()),
            )
            conn.commit()
            return User(id=cur.lastrowid, username=username, role=role)
        finally:
            conn.close()

    def list_users(self) -> list:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, username, role, disabled, created_at FROM users ORDER BY username"
            ).fetchall()
            return [{"id": r[0], "username": r[1], "role": r[2],
                    "disabled": bool(r[3]), "created_at": r[4]} for r in rows]
        finally:
            conn.close()

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        conn = self._connect()
        try:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
            conn.commit()
        finally:
            conn.close()

    def set_password(self, user_id: int, new_password: str) -> None:
        """Admin password reset — also used to rotate a user's credential."""
        if len(new_password) < 8:
            raise ValueError("password must be at least 8 characters")
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
        # Force re-login after an admin reset.
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
        token = secrets.token_urlsafe(32)
        now = time.time()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, user_id, now, now + _SESSION_TTL_SECONDS),
            )
            conn.commit()
            return token
        finally:
            conn.close()

    def resolve_session(self, token: str) -> Optional[User]:
        if not token:
            return None
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT u.id, u.username, u.role, u.disabled, s.expires_at "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
                (token,),
            ).fetchone()
            if row is None:
                return None
            user_id, username, role, disabled, expires_at = row
            if disabled or time.time() > expires_at:
                return None
            return User(id=user_id, username=username, role=role)
        finally:
            conn.close()

    def delete_session(self, token: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        finally:
            conn.close()

    def delete_all_sessions_for_user(self, user_id: int) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()


def get_default_store() -> AuthStore:
    return AuthStore()
