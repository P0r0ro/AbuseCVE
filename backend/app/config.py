"""AbuseCVE – Application configuration via Pydantic Settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List


class Settings(BaseSettings):
    # ── Database ──────────────────────────────────────
    database_url: str = Field(
        default="postgresql+asyncpg://abusecve:abusecve_dev_password@postgres:5432/abusecve"
    )
    database_url_sync: str = Field(default="")

    # ── Redis ─────────────────────────────────────────
    redis_url: str = Field(default="redis://redis:6379/0")

    # ── NVD API ───────────────────────────────────────
    nvd_api_key: str = Field(default="")

    # ── SMTP ──────────────────────────────────────────
    smtp_host: str = Field(default="smtp.gmail.com")
    smtp_port: int = Field(default=587)
    smtp_user: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_from: str = Field(default="")
    smtp_tls: bool = Field(default=True)
    alert_recipients: str = Field(default="")

    # ── Scheduler ─────────────────────────────────────
    scan_interval_minutes: int = Field(default=120)
    health_report_hour: int = Field(default=23)
    health_report_minute: int = Field(default=59)

    # ── AI (Knowledge Article generation) ────────────
    mistral_api_key: str = Field(default="")
    gemini_api_key: str = Field(default="")

    # ── App ───────────────────────────────────────────
    secret_key: str = Field(default="change_me")
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")

    @property
    def sync_database_url(self) -> str:
        if self.database_url_sync:
            return self.database_url_sync
        return self.database_url.replace("+asyncpg", "")

    @property
    def recipient_list(self) -> List[str]:
        if not self.alert_recipients:
            return []
        return [r.strip() for r in self.alert_recipients.split(",") if r.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
