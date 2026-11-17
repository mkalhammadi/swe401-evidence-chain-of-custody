"""Application configuration.

All values can be overridden with environment variables (see .env.example).
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    # SQLite by default so the project runs anywhere; set DATABASE_URL to use PostgreSQL,
    # e.g. postgresql+psycopg2://coc:coc@localhost:5432/coc
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "instance", "coc.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    EVIDENCE_STORE = os.environ.get(
        "EVIDENCE_STORE", os.path.join(BASE_DIR, "instance", "evidence_store")
    )
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", "200")) * 1024 * 1024
    HASH_CHUNK_SIZE = 64 * 1024  # files are hashed in 64 KB chunks (low memory use)

    # Scheduled integrity checks (minutes). 0 disables the background scheduler.
    INTEGRITY_CHECK_INTERVAL_MIN = int(os.environ.get("INTEGRITY_CHECK_INTERVAL_MIN", "60"))

    # Anomaly rules
    LOCAL_UTC_OFFSET_HOURS = int(os.environ.get("LOCAL_UTC_OFFSET_HOURS", "4"))  # UAE = UTC+4
    WORK_HOURS_START = int(os.environ.get("WORK_HOURS_START", "7"))   # 07:00
    WORK_HOURS_END = int(os.environ.get("WORK_HOURS_END", "19"))      # 19:00
    BULK_DOWNLOAD_LIMIT = int(os.environ.get("BULK_DOWNLOAD_LIMIT", "5"))
    BULK_DOWNLOAD_WINDOW_MIN = int(os.environ.get("BULK_DOWNLOAD_WINDOW_MIN", "10"))
    FAILED_LOGIN_LIMIT = int(os.environ.get("FAILED_LOGIN_LIMIT", "5"))
    LOCKOUT_MINUTES = int(os.environ.get("LOCKOUT_MINUTES", "15"))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 30 * 60  # 30 minutes idle timeout


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    INTEGRITY_CHECK_INTERVAL_MIN = 0
    WTF_CSRF_ENABLED = False
