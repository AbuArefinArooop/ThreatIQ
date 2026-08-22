"""
ThreatIQ v4.0 -- Central configuration via Pydantic Settings.
All values overridable via environment variables or .env file.
"""
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # -- App --------------------------------------------------------
    APP_NAME: str = "ThreatIQ"
    APP_VERSION: str = "4.0.0"
    ENVIRONMENT: str = "development"  # development | staging | production
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "change-this-in-production-via-env-var"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24h

    # -- Database (PostgreSQL) --------------------------------------
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "threatiq"
    POSTGRES_PASSWORD: str = "threatiq_dev_password"
    POSTGRES_DB: str = "threatiq"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def DATABASE_URL_SYNC(self) -> str:
        """Sync URL for Alembic migrations and Celery workers."""
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # -- Redis (cache + Celery broker) -------------------------------
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    def model_post_init(self, __context) -> None:
        if not self.CELERY_BROKER_URL:
            self.CELERY_BROKER_URL = self.REDIS_URL
        if not self.CELERY_RESULT_BACKEND:
            self.CELERY_RESULT_BACKEND = self.REDIS_URL

    # -- MISP connector ------------------------------------------------
    MISP_URL: Optional[str] = None
    MISP_API_KEY: Optional[str] = None
    MISP_VERIFY_SSL: bool = True

    # -- CIRCL connector -------------------------------------------------
    CIRCL_USERNAME: Optional[str] = None
    CIRCL_PASSWORD: Optional[str] = None
    CIRCL_BASE_URL: str = "https://www.circl.lu/api"

    # -- OTX (AlienVault) connector -- replaces FS-ISAC --------------------
    # Free key, no membership gate: https://otx.alienvault.com/api
    OTX_API_KEY: Optional[str] = "d82f8d639f6ece466e1501be55410b3481cfe3a976eb057707d41915d390d631"
    OTX_API_URL: str = "https://otx.alienvault.com/api/v1"

    # -- OpenCTI connector -----------------------------------------------
    OPENCTI_URL: Optional[str] = None
    OPENCTI_TOKEN: Optional[str] = None
    OPENCTI_CONNECTOR_ID: str = "threatiq-enrichment-connector"
    OPENCTI_CONNECTOR_NAME: str = "ThreatIQ AI Enrichment"
    OPENCTI_CONNECTOR_SCOPE: str = "IPv4-Addr,Domain-Name,File,Url,Indicator"
    OPENCTI_CONNECTOR_CONFIDENCE_LEVEL: int = 75
    OPENCTI_RUN_AND_TERMINATE: bool = False
    OPENCTI_LOG_LEVEL: str = "info"

    # -- ML / model artefact paths ----------------------------------------
    MODEL_DIR: str = "./model_artifacts"
    GAT_MODEL_PATH: str = "./model_artifacts/gat_model.pt"
    CLASSIFIER_MODEL_PATH: str = "./model_artifacts/classifier.joblib"
    TFIDF_VECTORIZER_PATH: str = "./model_artifacts/tfidf.joblib"
    MITRE_ATTACK_DATA_PATH: str = "./data/mitre_attack/enterprise-attack.json"

    # -- Rate limiting -------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 120


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
