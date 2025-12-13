import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "government-secure-key-change-in-production-2024"
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///government_zta.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "jwt-government-secure-key-2024")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # OPA Configuration
    OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
    OPA_TIMEOUT = int(os.environ.get("OPA_TIMEOUT", 5))

    # mTLS Configuration
    SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "./certs")

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
