"""
Centralised settings loaded from .env via pydantic-settings
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/bruteforce_db"
    SYNC_DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/bruteforce_db"

    # JWT
    SECRET_KEY: str = "change-me-in-production-at-least-32-chars!!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # App
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    DEBUG: bool = True

    # ML
    MODEL_PATH: str = "ml/model.joblib"
    SCALER_PATH: str = "ml/scaler.joblib"
    ANOMALY_THRESHOLD: float = 0.5

    # Security rules
    MAX_FAILED_ATTEMPTS_PER_IP: int = 10
    MAX_FAILED_WINDOW_SECONDS: int = 300
    BLOCK_DURATION_SECONDS: int = 3600
    SPRAY_UNIQUE_USERS_THRESHOLD: int = 5
    STUFFING_UNIQUE_IPS_THRESHOLD: int = 10


settings = Settings()
