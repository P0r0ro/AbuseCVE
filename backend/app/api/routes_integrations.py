"""Integrations API routes – CRUD for webhook/CRM configurations."""

from __future__ import annotations

import logging
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.database import get_db
from app.models.integration import Integration

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/integrations", tags=["Integrations"])


class IntegrationCreate(BaseModel):
    name: str
    type: str = "webhook"  # webhook, ms_crm, jira, custom
    url: str
    method: str = "POST"
    headers: Dict[str, str] = {}
    auth_type: Optional[str] = None  # none, bearer, basic, api_key
    auth_token: Optional[str] = None
    payload_template: Optional[str] = None
    enabled: bool = True


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    url: Optional[str] = None
    method: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    auth_type: Optional[str] = None
    auth_token: Optional[str] = None
    payload_template: Optional[str] = None
    enabled: Optional[bool] = None


@router.get("")
async def list_integrations(db: AsyncSession = Depends(get_db)):
    """List all integration configurations."""
    result = await db.execute(select(Integration).order_by(Integration.created_at.desc()))
    return [i.to_dict() for i in result.scalars().all()]


@router.post("", status_code=201)
async def create_integration(data: IntegrationCreate, db: AsyncSession = Depends(get_db)):
    """Create a new integration."""
    integration = Integration(
        name=data.name,
        type=data.type,
        url=data.url,
        method=data.method,
        headers=data.headers,
        auth_type=data.auth_type,
        auth_token=data.auth_token,
        payload_template=data.payload_template,
        enabled=data.enabled,
    )
    db.add(integration)
    await db.flush()
    return integration.to_dict()


@router.get("/{integration_id}")
async def get_integration(integration_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    return integration.to_dict()


@router.put("/{integration_id}")
async def update_integration(
    integration_id: int, data: IntegrationUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    update_data = data.model_dump(exclude_unset=True)
    # Don't overwrite auth_token with masked value
    if update_data.get("auth_token", "").startswith("***"):
        del update_data["auth_token"]

    for key, value in update_data.items():
        setattr(integration, key, value)
    await db.flush()
    return integration.to_dict()


@router.delete("/{integration_id}")
async def delete_integration(integration_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    await db.delete(integration)
    await db.flush()
    return {"message": "Integration deleted"}


@router.post("/{integration_id}/toggle")
async def toggle_integration(integration_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    integration.enabled = not integration.enabled
    await db.flush()
    return integration.to_dict()


@router.post("/{integration_id}/test")
async def test_integration(integration_id: int, db: AsyncSession = Depends(get_db)):
    """Send a test payload to the integration endpoint."""
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    from app.services.webhook_service import dispatch_webhook

    test_payload = {
        "event": "test",
        "source": "AbuseCVE",
        "timestamp": datetime.utcnow().isoformat(),
        "cve": {
            "cve_id": "CVE-2024-00000",
            "vendor": "TestVendor",
            "product": "TestProduct",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "description": "This is a test alert from AbuseCVE integration test.",
            "source": "NVD",
            "kev_flag": False,
        },
        "rule_name": "[TEST] Integration Test",
    }

    try:
        result = await dispatch_webhook(integration, test_payload)
        # Update integration status
        integration.last_used = datetime.utcnow()
        integration.last_status = result.get("status", "unknown")
        integration.last_error = result.get("error")
        await db.flush()
        return result
    except Exception as e:
        integration.last_used = datetime.utcnow()
        integration.last_status = "failed"
        integration.last_error = str(e)
        await db.flush()
        return {"status": "failed", "error": str(e)}
