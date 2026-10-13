import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "Aegis — Quantum-Safe AI Threat Detection System"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "super-secret-aegis-key-change-in-prod"
    
    # Storage Paths
    BASE_DIR: Path = BASE_DIR
    MODEL_PATH: Path = BASE_DIR / "models" / "aegis_ids_xgboost.joblib"
    SCALER_PATH: Path = BASE_DIR / "models" / "aegis_ids_scaler.joblib"
    METADATA_PATH: Path = BASE_DIR / "models" / "aegis_ids_metadata.joblib"
    DATA_DIR: Path = BASE_DIR / "data"
    
    # ML & MLflow Settings
    MLFLOW_TRACKING_URI: str = f"sqlite:///{BASE_DIR / 'mlflow.db'}"
    MODEL_VERSION: str = "aegis-ids/v1.0.0"
    
    # Database & Redis Settings
    DATABASE_URL: str = "sqlite:///" + str(BASE_DIR / "aegis.db")
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Crypto Settings
    PQC_ALGORITHM: str = "ML-KEM-768"
    KEY_ROTATION_INTERVAL_HOURS: int = 24
    
    # API Settings
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    # Optional API key to protect detection endpoint
    DETECT_API_KEY: Optional[str] = None
    # Rate limit (per key or per IP) allowed requests per minute for /api/detect
    RATE_LIMIT_PER_MINUTE: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
