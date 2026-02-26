"""Configuration API routes – runtime config and SMTP settings."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config import settings

router = APIRouter(prefix="/api/config", tags=["Configuration"])


class ConfigUpdate(BaseModel):
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_tls: Optional[bool] = None
    alert_recipients: Optional[str] = None
    scan_interval_minutes: Optional[int] = None
    health_report_hour: Optional[int] = None
    health_report_minute: Optional[int] = None
    nvd_api_key: Optional[str] = None
    mistral_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None


def _mask_key(key: str) -> str:
    """Mask an API key, showing last 4 chars."""
    if not key:
        return ""
    if len(key) > 4:
        return "***" + key[-4:]
    return "***"


@router.get("")
async def get_config():
    """Get current configuration (sensitive fields masked)."""
    return {
        "smtp_host": settings.smtp_host,
        "smtp_port": settings.smtp_port,
        "smtp_user": settings.smtp_user,
        "smtp_password": "***" if settings.smtp_password else "",
        "smtp_from": settings.smtp_from,
        "smtp_tls": settings.smtp_tls,
        "alert_recipients": settings.alert_recipients,
        "scan_interval_minutes": settings.scan_interval_minutes,
        "health_report_hour": settings.health_report_hour,
        "health_report_minute": settings.health_report_minute,
        "nvd_api_key": _mask_key(settings.nvd_api_key),
        "mistral_api_key": _mask_key(settings.mistral_api_key),
        "gemini_api_key": _mask_key(settings.gemini_api_key),
        "app_env": settings.app_env,
    }


@router.put("")
async def update_config(data: ConfigUpdate):
    """Update runtime configuration.

    Note: This updates the in-memory settings. For persistence across restarts,
    update .env file.
    """
    update_data = data.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        if hasattr(settings, key):
            # Pydantic v2 settings are mutable via __dict__
            object.__setattr__(settings, key, value)

    return {"message": "Configuration updated", "updated_fields": list(update_data.keys())}
