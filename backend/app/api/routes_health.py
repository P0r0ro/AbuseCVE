"""Health report API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.health_report import HealthReport
from app.services.health_service import generate_daily_report, check_component_health

router = APIRouter(prefix="/api/health-reports", tags=["Health Reports"])


@router.get("")
async def list_reports(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(HealthReport).order_by(HealthReport.report_date.desc()).limit(30)
    )
    return [r.to_dict() for r in result.scalars().all()]


@router.get("/status")
async def component_status():
    """Get current component health status."""
    return await check_component_health()


@router.post("/generate")
async def generate_report(db: AsyncSession = Depends(get_db)):
    """Manually trigger a health report."""
    report = await generate_daily_report(db)
    return report


@router.post("/send")
async def generate_and_send(db: AsyncSession = Depends(get_db)):
    """Generate and send a health report via email."""
    report = await generate_daily_report(db)
    from app.services.smtp_service import send_health_report
    email_result = await send_health_report(report)
    return {"report": report, "email": email_result}
