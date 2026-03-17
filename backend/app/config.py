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

    # ── Per-type email routing ─────────────────────────
    # Each defaults to ALERT_RECIPIENTS if not set.
    # HEALTH_RECIPIENTS: who receives daily health check emails (admin/ops team)
    # SCAN_RECIPIENTS: who receives scan summary emails with 0 alerts (admin/debug)
    # WEBHOOK_EMAIL: email address used for CRM/webhook integration notifications
    health_recipients: str = Field(default="")
    scan_recipients: str = Field(default="")
    webhook_email: str = Field(default="")

    # ── Scheduler ─────────────────────────────────────
    scan_interval_minutes: int = Field(default=120)
    health_report_hour: int = Field(default=23)
    health_report_minute: int = Field(default=59)

    # ── AI (Knowledge Article generation) ────────────
    mistral_api_key: str = Field(default="")
    gemini_api_key: str = Field(default="")

    # ── AI (LLM vendor/product extraction) ─────────
    groq_api_key: str = Field(default="")

    # ── App ───────────────────────────────────────────
    secret_key: str = Field(default="change_me")
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")
    rules_file_path: str = Field(default="", description="Path to filter rules YAML (auto-detected if empty)")

    @property
    def sync_database_url(self) -> str:
        if self.database_url_sync:
            return self.database_url_sync
        return self.database_url.replace("+asyncpg", "")

    @property
    def recipient_list(self) -> List[str]:
        """Default alert recipients (analysts) — used for CVE alert emails."""
        if not self.alert_recipients:
            return []
        return [r.strip() for r in self.alert_recipients.split(",") if r.strip()]

    @property
    def health_recipient_list(self) -> List[str]:
        """Recipients for health check emails. Falls back to alert_recipients."""
        if self.health_recipients:
            return [r.strip() for r in self.health_recipients.split(",") if r.strip()]
        return self.recipient_list

    @property
    def scan_recipient_list(self) -> List[str]:
        """Recipients for scan summary emails (0-alert scans). Falls back to alert_recipients."""
        if self.scan_recipients:
            return [r.strip() for r in self.scan_recipients.split(",") if r.strip()]
        return self.recipient_list

    @property
    def webhook_email_address(self) -> str:
        """Email for CRM/webhook integration. Falls back to smtp_from or smtp_user."""
        return self.webhook_email or self.smtp_from or self.smtp_user

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
