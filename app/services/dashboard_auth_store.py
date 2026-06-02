"""Dashboard account, session, and API key storage."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote_plus

import psycopg
from psycopg.rows import dict_row

from app.core.config import settings


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _build_postgres_dsn() -> str:
    if settings.DATABASE_URL:
        return settings.DATABASE_URL

    password = quote_plus(settings.POSTGRES_PASSWORD or settings.DB_PASSWORD or "")
    user = quote_plus(settings.POSTGRES_USER or settings.DB_USER or "")
    host = settings.POSTGRES_HOST or settings.DB_HOST or "localhost"
    port = settings.POSTGRES_PORT or settings.DB_PORT or 5432
    database = settings.POSTGRES_DB or settings.DB_NAME or ""
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _format_datetime(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class DashboardAuthStore:
    """PostgreSQL-backed dashboard auth store."""

    def __init__(self, *, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or _build_postgres_dsn()
        self._init_schema()

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.dsn, row_factory=dict_row)

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simba_dashboard_users (
                    id TEXT PRIMARY KEY,
                    github_id TEXT UNIQUE NOT NULL,
                    github_login TEXT NOT NULL,
                    email TEXT,
                    name TEXT,
                    avatar_url TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    last_login_at TIMESTAMPTZ
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simba_dashboard_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES simba_dashboard_users(id) ON DELETE CASCADE,
                    session_token_hash TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_simba_dashboard_sessions_token
                ON simba_dashboard_sessions(session_token_hash)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simba_api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES simba_dashboard_users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    last_used_at TIMESTAMPTZ,
                    revoked_at TIMESTAMPTZ
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_simba_api_keys_hash
                ON simba_api_keys(key_hash)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_simba_api_keys_user
                ON simba_api_keys(user_id, created_at DESC)
                """
            )

    def upsert_github_user(self, profile: dict[str, Any], email: Optional[str]) -> dict[str, Any]:
        now = _utc_now()
        github_id = str(profile["id"])
        github_login = profile.get("login") or github_id
        name = profile.get("name") or github_login
        avatar_url = profile.get("avatar_url")

        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM simba_dashboard_users WHERE github_id = %s",
                (github_id,),
            ).fetchone()
            if row is None:
                user_id = uuid.uuid4().hex
                connection.execute(
                    """
                    INSERT INTO simba_dashboard_users (
                        id, github_id, github_login, email, name, avatar_url,
                        created_at, updated_at, last_login_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (user_id, github_id, github_login, email, name, avatar_url, now, now, now),
                )
            else:
                user_id = row["id"]
                connection.execute(
                    """
                    UPDATE simba_dashboard_users
                    SET github_login = %s,
                        email = %s,
                        name = %s,
                        avatar_url = %s,
                        updated_at = %s,
                        last_login_at = %s
                    WHERE id = %s
                    """,
                    (github_login, email or row["email"], name, avatar_url, now, now, user_id),
                )
        user = self.get_user(user_id)
        if user is None:
            raise RuntimeError("Dashboard user was not persisted")
        return user

    def get_user(self, user_id: str) -> Optional[dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM simba_dashboard_users WHERE id = %s",
                (user_id,),
            ).fetchone()
        return self._user_row_to_dict(row) if row else None

    def create_session(self, user_id: str, *, days: int = 14) -> str:
        token = secrets.token_urlsafe(40)
        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO simba_dashboard_sessions (
                    id, user_id, session_token_hash, created_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (uuid.uuid4().hex, user_id, _hash_secret(token), now, now + timedelta(days=days)),
            )
        return token

    def get_user_by_session_token(self, token: Optional[str]) -> Optional[dict[str, Any]]:
        if not token:
            return None
        now = _utc_now()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT u.*
                FROM simba_dashboard_sessions s
                JOIN simba_dashboard_users u ON u.id = s.user_id
                WHERE s.session_token_hash = %s
                  AND s.revoked_at IS NULL
                  AND s.expires_at > %s
                """,
                (_hash_secret(token), now),
            ).fetchone()
        return self._user_row_to_dict(row) if row else None

    def revoke_session(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE simba_dashboard_sessions
                SET revoked_at = %s
                WHERE session_token_hash = %s AND revoked_at IS NULL
                """,
                (_utc_now(), _hash_secret(token)),
            )

    def list_api_keys(self, user_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, name, key_prefix, created_at, last_used_at, revoked_at
                FROM simba_api_keys
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [self._api_key_row_to_dict(row) for row in rows]

    def create_api_key(self, user_id: str, name: str) -> dict[str, Any]:
        clean_name = name.strip()[:80] or "Cle API Simba"
        raw_key = f"sk_simba_{secrets.token_urlsafe(32)}"
        now = _utc_now()
        key_id = uuid.uuid4().hex
        key_prefix = raw_key[:18]
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO simba_api_keys (
                    id, user_id, name, key_hash, key_prefix, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (key_id, user_id, clean_name, _hash_secret(raw_key), key_prefix, now),
            )
        return {
            "id": key_id,
            "name": clean_name,
            "key_prefix": key_prefix,
            "api_key": raw_key,
            "created_at": now.isoformat(),
            "last_used_at": None,
            "revoked_at": None,
        }

    def revoke_api_key(self, *, user_id: str, key_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE simba_api_keys
                SET revoked_at = %s
                WHERE id = %s AND user_id = %s AND revoked_at IS NULL
                """,
                (_utc_now(), key_id, user_id),
            )
        return cursor.rowcount > 0

    def validate_api_key(self, api_key: Optional[str]) -> bool:
        if not api_key:
            return False
        if settings.API_KEY and hmac.compare_digest(api_key, settings.API_KEY):
            return True

        key_hash = _hash_secret(api_key)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id FROM simba_api_keys
                WHERE key_hash = %s AND revoked_at IS NULL
                """,
                (key_hash,),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "UPDATE simba_api_keys SET last_used_at = %s WHERE id = %s",
                (_utc_now(), row["id"]),
            )
        return True

    def _user_row_to_dict(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "github_id": row["github_id"],
            "github_login": row["github_login"],
            "email": row["email"],
            "name": row["name"],
            "avatar_url": row["avatar_url"],
            "created_at": _format_datetime(row["created_at"]),
            "updated_at": _format_datetime(row["updated_at"]),
            "last_login_at": _format_datetime(row["last_login_at"]),
        }

    def _api_key_row_to_dict(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "key_prefix": row["key_prefix"],
            "created_at": _format_datetime(row["created_at"]),
            "last_used_at": _format_datetime(row["last_used_at"]),
            "revoked_at": _format_datetime(row["revoked_at"]),
        }


_store: Optional[DashboardAuthStore] = None


def get_dashboard_auth_store() -> DashboardAuthStore:
    global _store
    if _store is None:
        _store = DashboardAuthStore()
    return _store
