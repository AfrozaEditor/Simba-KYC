from pathlib import Path
from typing import Optional

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def _normalize_boolish(value):
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"release", "prod", "production"}:
            return False
        if normalized in {"debug", "dev", "development"}:
            return True
    return value


class Settings(BaseSettings):
    """Configuration globale pour Simba KYC."""
    model_config = SettingsConfigDict(
        case_sensitive=True,
        extra="allow",
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
    )

    # FastAPI
    APP_NAME: str = "Simba KYC"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    EXPOSE_API_DOCS: bool = False

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8001

    # Timeouts
    KYC_ANALYZE_TIMEOUT: int = 30
    HEALTH_TIMEOUT: int = 2

    # === LLM MULTIMODAUX ===
    USE_LLM_MULTIMODAL: bool = True
    LLM_PREFER_PROVIDER: str = "groq"
    LLM_FALLBACK_CHAIN: list = ["groq"]
    LLM_USE_ALL_PROVIDERS: bool = False

    # === Groq (LLM multimodal principal) ===
    # Clé sur: https://console.groq.com
    # Format: gsk_xxxxxxxxxxxxxxxxxxxx
    GROQ_API_KEY: Optional[str] = None
    GROQ_API_KEYS: Optional[str] = None
    GROQ_API_BASE: str = "https://api.groq.com/openai/v1"  
    GROQ_MODEL: str = "meta-llama/llama-4-scout-17b-16e-instruct"  
    GROQ_TIMEOUT: int = 30

    # LLM Confidence Thresholds
    LLM_MIN_CONFIDENCE: float = 0.70
    LLM_MIN_CONFIDENCE_ID: float = 0.70
    LLM_MIN_CONFIDENCE_NAME: float = 0.65
    LLM_MIN_CONFIDENCE_DATE: float = 0.75

    # AWS Rekognition (Liveness)
    AWS_REGION: str = "eu-west-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_SESSION_TOKEN: Optional[str] = None
    AWS_LIVENESS_MIN_CONFIDENCE: float = 0.85

    # Simba KYC utilise AWS Rekognition pour la liveness.
    LIVENESS_PROVIDER: str = "aws"

    # Auth
    API_KEY: Optional[str] = None
    ALLOW_ANONYMOUS: bool = False
    DASHBOARD_SESSION_SECRET: Optional[str] = None
    DASHBOARD_COOKIE_NAME: str = "simba_dashboard_session"
    DASHBOARD_BASE_URL: Optional[str] = None
    GITHUB_OAUTH_CLIENT_ID: Optional[str] = None
    GITHUB_OAUTH_CLIENT_SECRET: Optional[str] = None

    # Logging
    LOG_LEVEL: str = "INFO"

    # CORS
    ALLOWED_ORIGINS: list = ["*"]

    # Dashboard runtime storage
    DASHBOARD_DATA_DIR: str = str(Path(__file__).resolve().parents[2] / "data")
    DASHBOARD_ASSET_DIR: Optional[str] = None

    # PostgreSQL dashboard persistence. DATABASE_URL wins when defined.
    # POSTGRES_* mirrors the existing Django backend configuration.
    DATABASE_URL: Optional[str] = None
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5433
    POSTGRES_USER: str = "Afroza_Solidarity_user"
    POSTGRES_PASSWORD: Optional[str] = "Afroza_Solidarity_password"
    POSTGRES_DB: str = "Afroza_Solidarity_db"

    # Compatibility aliases for old external env files.
    DB_HOST: Optional[str] = None
    DB_PORT: Optional[int] = None
    DB_USER: Optional[str] = None
    DB_PASSWORD: Optional[str] = None
    DB_NAME: Optional[str] = None

    @field_validator("DEBUG", mode="before")
    @classmethod
    def _coerce_debug(cls, value):
        return _normalize_boolish(value)

    @model_validator(mode="after")
    def _coerce_provider_config(self):
        if self.GROQ_API_KEY:
            self.GROQ_API_KEY = self.GROQ_API_KEY.strip()
            return self

        raw_keys = (self.GROQ_API_KEYS or "").strip()
        if not raw_keys:
            return self

        self.GROQ_API_KEY = next(
            (item.strip() for item in raw_keys.split(",") if item.strip()),
            None,
        )
        return self


settings = Settings()
