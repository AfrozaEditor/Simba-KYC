"""PostgreSQL store for KYC dashboard requests, assets, and events."""

from __future__ import annotations

import base64
import json
import mimetypes
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote_plus

import psycopg
from psycopg.rows import dict_row

from app.core.config import settings
from app.core.models.kyc_result import KYCResult


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(value: Any) -> str:
    if value is None:
        return "null"
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, ensure_ascii=False, default=str)


def _json_loads(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _resolve_path(value: Optional[str], fallback: Path) -> Path:
    if not value:
        return fallback
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def _safe_filename(value: Optional[str], fallback: str) -> str:
    candidate = (value or fallback).strip() or fallback
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "-", candidate)
    return candidate.strip(".-") or fallback


def _split_data_url(value: str) -> str:
    return value.split(",", 1)[1] if "," in value else value


def _detect_image_type(content: bytes, fallback: Optional[str]) -> tuple[str, str]:
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "image/webp", ".webp"

    content_type = fallback or "application/octet-stream"
    extension = mimetypes.guess_extension(content_type) or ".bin"
    return content_type, extension


def _build_postgres_dsn() -> str:
    if settings.DATABASE_URL:
        return settings.DATABASE_URL

    password = quote_plus(settings.POSTGRES_PASSWORD or settings.DB_PASSWORD or "")
    user = quote_plus(settings.POSTGRES_USER or settings.DB_USER or "")
    host = settings.POSTGRES_HOST or settings.DB_HOST or "localhost"
    port = settings.POSTGRES_PORT or settings.DB_PORT or 5432
    database = settings.POSTGRES_DB or settings.DB_NAME or ""
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


def build_review_suggestions(result: KYCResult) -> list[str]:
    """Build concise review hints from a KYC result."""

    suggestions: list[str] = []
    if result.reason:
        suggestions.append(result.reason)

    if result.liveness:
        if not result.liveness.passed:
            suggestions.append("Selfie a reprendre: liveness non valide.")
        if result.liveness.quality_score is not None and result.liveness.quality_score < 0.65:
            suggestions.append("Qualite selfie faible: demander une image plus nette et mieux eclairee.")
        if result.liveness.face_count not in (None, 1):
            suggestions.append("Selfie ambigu: verifier le nombre de visages detectes.")

    fraud = result.fraud_indicators
    if fraud:
        if fraud.face_match_score < 0.80:
            suggestions.append("Correspondance faciale faible: verifier selfie et portrait document.")
        if fraud.document_integrity < 0.75:
            suggestions.append("Integrite documentaire faible: verifier les traces de modification.")
        for item in fraud.criteria_results:
            if item.status == "FAIL":
                suggestions.append(f"{item.criterion_id}: {item.reason}")

    if result.qr_confidence is not None and result.qr_confidence < 0.60:
        suggestions.append("QR documentaire faible ou absent: verifier le verso du document.")
    if result.mrz_confidence is not None and result.mrz_confidence < 0.60:
        suggestions.append("MRZ faible ou absente: verifier la zone MRZ du document.")

    deduped: list[str] = []
    for suggestion in suggestions:
        if suggestion and suggestion not in deduped:
            deduped.append(suggestion)
    return deduped[:12]


class KYCDashboardStore:
    """PostgreSQL-backed KYC dashboard storage."""

    def __init__(
        self,
        *,
        data_dir: Optional[str] = None,
        asset_dir: Optional[str] = None,
        dsn: Optional[str] = None,
    ) -> None:
        base_dir = _resolve_path(data_dir or settings.DASHBOARD_DATA_DIR, Path.cwd() / "data")
        self.asset_dir = _resolve_path(asset_dir or settings.DASHBOARD_ASSET_DIR, base_dir / "assets")
        self.asset_dir.mkdir(parents=True, exist_ok=True)
        self.dsn = dsn or _build_postgres_dsn()
        self._init_schema()

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.dsn, row_factory=dict_row)

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simba_kyc_requests (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    decision TEXT,
                    recommendation TEXT,
                    valid BOOLEAN,
                    kyc_score INTEGER,
                    reason TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    result_json JSONB,
                    kyc_data_json JSONB,
                    liveness_json JSONB,
                    fraud_json JSONB,
                    qr_data_json JSONB,
                    mrz_data_json JSONB,
                    source_checks_json JSONB,
                    suggestions_json JSONB,
                    error TEXT,
                    reviewer_id TEXT,
                    review_reason TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    completed_at TIMESTAMPTZ,
                    reviewed_at TIMESTAMPTZ
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_simba_kyc_requests_created_at
                ON simba_kyc_requests(created_at DESC)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_simba_kyc_requests_status
                ON simba_kyc_requests(status)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simba_kyc_assets (
                    id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL REFERENCES simba_kyc_requests(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_simba_kyc_assets_request_id
                ON simba_kyc_assets(request_id)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simba_kyc_events (
                    id BIGSERIAL PRIMARY KEY,
                    request_id TEXT NOT NULL REFERENCES simba_kyc_requests(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )

    def create_request(self, *, user_id: str, source: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        request_id = uuid.uuid4().hex
        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO simba_kyc_requests (
                    id, user_id, source, status, metadata_json, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)
                """,
                (request_id, user_id, source, "PROCESSING", _json_dumps(metadata), now, now),
            )
        return self.get_request(request_id) or {"id": request_id, "user_id": user_id, "status": "PROCESSING"}

    def add_asset_base64(
        self,
        *,
        request_id: str,
        kind: str,
        image_base64: Optional[str],
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not image_base64:
            return None

        content = base64.b64decode(_split_data_url(image_base64), validate=True)
        detected_type, extension = _detect_image_type(content, content_type)
        asset_id = uuid.uuid4().hex
        safe_name = _safe_filename(filename, f"{kind}{extension}")
        if "." not in safe_name:
            safe_name = f"{safe_name}{extension}"

        request_dir = self.asset_dir / request_id
        request_dir.mkdir(parents=True, exist_ok=True)
        storage_path = request_dir / f"{kind}-{asset_id}-{safe_name}"
        storage_path.write_bytes(content)

        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO simba_kyc_assets (
                    id, request_id, kind, filename, content_type, storage_path, size_bytes, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    asset_id,
                    request_id,
                    kind,
                    safe_name,
                    detected_type,
                    str(storage_path),
                    len(content),
                    now,
                ),
            )
        return self.get_asset(asset_id)

    def mark_completed(self, request_id: str, result: KYCResult) -> Dict[str, Any]:
        now = _utc_now()
        suggestions = build_review_suggestions(result)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE simba_kyc_requests
                SET status = %s,
                    decision = %s,
                    recommendation = %s,
                    valid = %s,
                    kyc_score = %s,
                    reason = %s,
                    result_json = %s::jsonb,
                    kyc_data_json = %s::jsonb,
                    liveness_json = %s::jsonb,
                    fraud_json = %s::jsonb,
                    qr_data_json = %s::jsonb,
                    mrz_data_json = %s::jsonb,
                    source_checks_json = %s::jsonb,
                    suggestions_json = %s::jsonb,
                    error = NULL,
                    updated_at = %s,
                    completed_at = %s
                WHERE id = %s
                """,
                (
                    result.status.value,
                    result.status.value,
                    result.recommendation,
                    result.valid,
                    result.kyc_score,
                    result.reason,
                    _json_dumps(result),
                    _json_dumps(result.kyc_data),
                    _json_dumps(result.liveness),
                    _json_dumps(result.fraud_indicators),
                    _json_dumps(result.qr_data),
                    _json_dumps(result.mrz_data),
                    _json_dumps(result.source_checks),
                    _json_dumps(suggestions),
                    now,
                    now,
                    request_id,
                ),
            )
        return self.get_request(request_id) or {"id": request_id, "status": result.status.value}

    def mark_failed(self, request_id: str, error: str) -> Dict[str, Any]:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE simba_kyc_requests
                SET status = %s, decision = %s, error = %s, updated_at = %s, completed_at = %s
                WHERE id = %s
                """,
                ("ERROR", "ERROR", error, now, now, request_id),
            )
        return self.get_request(request_id) or {"id": request_id, "status": "ERROR", "error": error}

    def apply_manual_decision(
        self,
        *,
        request_id: str,
        decision: str,
        reason: Optional[str],
        reviewer_id: Optional[str],
    ) -> Dict[str, Any]:
        decision = decision.upper()
        if decision not in {"APPROVED", "REJECTED", "MANUAL_REVIEW"}:
            raise ValueError("decision must be APPROVED, REJECTED or MANUAL_REVIEW")

        now = _utc_now()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE simba_kyc_requests
                SET status = %s,
                    decision = %s,
                    review_reason = %s,
                    reviewer_id = %s,
                    reviewed_at = %s,
                    updated_at = %s
                WHERE id = %s
                """,
                (decision, decision, reason, reviewer_id, now, now, request_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(request_id)
        return self.get_request(request_id) or {"id": request_id, "status": decision}

    def add_event(self, *, request_id: str, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        now = _utc_now()
        event = {
            "type": event_type,
            "request_id": request_id,
            "created_at": now,
            "payload": payload,
        }
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO simba_kyc_events (request_id, event_type, payload_json, created_at)
                VALUES (%s, %s, %s::jsonb, %s)
                """,
                (request_id, event_type, _json_dumps(payload), now),
            )
        return event

    def list_requests(
        self,
        *,
        status: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = %s")
            params.append(status.upper())
        if user_id:
            clauses.append("user_id = %s")
            params.append(user_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([max(1, min(limit, 200)), max(0, offset)])
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM simba_kyc_requests
                {where}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                params,
            ).fetchall()
        return [self._row_to_summary(row) for row in rows]

    def get_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM simba_kyc_requests WHERE id = %s",
                (request_id,),
            ).fetchone()
            if row is None:
                return None
            assets = connection.execute(
                "SELECT * FROM simba_kyc_assets WHERE request_id = %s ORDER BY created_at ASC",
                (request_id,),
            ).fetchall()
            events = connection.execute(
                """
                SELECT event_type, payload_json, created_at
                FROM simba_kyc_events
                WHERE request_id = %s
                ORDER BY id ASC
                """,
                (request_id,),
            ).fetchall()

        detail = self._row_to_detail(row)
        detail["assets"] = [self._asset_row_to_dict(asset) for asset in assets]
        detail["events"] = [
            {
                "type": event["event_type"],
                "created_at": self._format_datetime(event["created_at"]),
                "payload": _json_loads(event["payload_json"], {}),
            }
            for event in events
        ]
        return detail

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM simba_kyc_assets WHERE id = %s",
                (asset_id,),
            ).fetchone()
        return self._asset_row_to_dict(row, include_storage_path=True) if row else None

    def _row_to_summary(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "source": row["source"],
            "status": row["status"],
            "decision": row["decision"],
            "recommendation": row["recommendation"],
            "valid": row["valid"],
            "kyc_score": row["kyc_score"],
            "reason": row["reason"],
            "error": row["error"],
            "reviewer_id": row["reviewer_id"],
            "review_reason": row["review_reason"],
            "created_at": self._format_datetime(row["created_at"]),
            "updated_at": self._format_datetime(row["updated_at"]),
            "completed_at": self._format_datetime(row["completed_at"]),
            "reviewed_at": self._format_datetime(row["reviewed_at"]),
            "suggestions": _json_loads(row["suggestions_json"], []),
        }

    def _row_to_detail(self, row: Dict[str, Any]) -> Dict[str, Any]:
        detail = self._row_to_summary(row)
        detail.update(
            {
                "metadata": _json_loads(row["metadata_json"], {}),
                "result": _json_loads(row["result_json"], None),
                "kyc_data": _json_loads(row["kyc_data_json"], None),
                "liveness": _json_loads(row["liveness_json"], None),
                "fraud_indicators": _json_loads(row["fraud_json"], None),
                "qr_data": _json_loads(row["qr_data_json"], None),
                "mrz_data": _json_loads(row["mrz_data_json"], None),
                "source_checks": _json_loads(row["source_checks_json"], None),
            }
        )
        return detail

    def _asset_row_to_dict(
        self,
        row: Dict[str, Any],
        *,
        include_storage_path: bool = False,
    ) -> Dict[str, Any]:
        asset = {
            "id": row["id"],
            "request_id": row["request_id"],
            "kind": row["kind"],
            "filename": row["filename"],
            "content_type": row["content_type"],
            "size_bytes": row["size_bytes"],
            "created_at": self._format_datetime(row["created_at"]),
            "url": f"/api/v1/dashboard/assets/{row['id']}",
        }
        if include_storage_path:
            asset["storage_path"] = row["storage_path"]
        return asset

    @staticmethod
    def _format_datetime(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)


_store: Optional[KYCDashboardStore] = None


def get_kyc_dashboard_store() -> KYCDashboardStore:
    global _store
    if _store is None:
        _store = KYCDashboardStore()
    return _store
