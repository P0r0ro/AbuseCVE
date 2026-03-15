"""Test API routes – validates the full process chain works end-to-end."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db

router = APIRouter(prefix="/api/test", tags=["Test"])


@router.post("/smtp")
async def test_smtp():
    """Send a test email to verify SMTP configuration."""
    from app.services.smtp_service import send_test_email
    result = await send_test_email()
    return {"step": "smtp", "result": result}


@router.post("/fetch")
async def test_fetch():
    """Test CVE fetching from NVD (small sample)."""
    from app.engine.sources.nvd import NVDSource
    from datetime import datetime, timedelta

    nvd = NVDSource()
    since = datetime.utcnow() - timedelta(days=1)
    try:
        cves = await nvd.fetch_recent(since=since)
        return {
            "step": "fetch",
            "status": "ok",
            "cves_fetched": len(cves),
            "sample": [
                {"cve_id": c.cve_id, "vendor": c.vendor, "severity": c.severity}
                for c in cves[:5]
            ],
        }
    except Exception as e:
        return {"step": "fetch", "status": "error", "error": str(e)}


@router.post("/filter")
async def test_filter(db: AsyncSession = Depends(get_db)):
    """Test the filter engine with current rules against recent CVEs."""
    from app.engine.sources.nvd import NVDSource
    from app.engine.filter_engine import filter_cves
    from app.engine.rule_loader import get_rules
    from datetime import datetime, timedelta

    # Fetch recent CVEs
    nvd = NVDSource()
    since = datetime.utcnow() - timedelta(days=1)
    try:
        cves = await nvd.fetch_recent(since=since)
    except Exception as e:
        return {"step": "filter", "status": "error", "error": f"Fetch failed: {e}"}

    # Load rules from config file
    rules = [r for r in get_rules() if r.get("enabled", True)]

    if not rules:
        return {"step": "filter", "status": "warning", "message": "No active filter rules configured"}

    # Apply filters
    matches = filter_cves(cves, rules)

    return {
        "step": "filter",
        "status": "ok",
        "total_cves": len(cves),
        "active_rules": len(rules),
        "matches": len(matches),
        "matched_cves": [
            {"cve_id": m.cve.cve_id, "vendor": m.cve.vendor, "rule": m.rule_name}
            for m in matches[:10]
        ],
    }


@router.post("/pipeline")
async def test_pipeline(db: AsyncSession = Depends(get_db)):
    """Test the full pipeline: fetch → filter → dedup (no alerting)."""
    from app.engine.pipeline import CVEPipeline

    pipeline = CVEPipeline()
    try:
        result = await pipeline.run_full_cycle(db)
        return {
            "step": "pipeline",
            "status": "ok",
            "total_fetched": result.get("total_fetched", 0),
            "filtered": result.get("filtered_count", 0),
            "new_cves": len(result.get("new_cves", [])),
            "existing": result.get("existing_count", 0),
        }
    except Exception as e:
        return {"step": "pipeline", "status": "error", "error": str(e)}


@router.post("/full-chain")
async def test_full_chain(db: AsyncSession = Depends(get_db)):
    """Run the complete process chain test: fetch → filter → dedup → alert."""
    results = []

    # Step 1: SMTP test
    from app.services.smtp_service import send_test_email
    smtp_result = await send_test_email()
    results.append({"step": "smtp", "status": smtp_result.get("status", "unknown")})

    # Step 2: Fetch test
    from app.engine.sources.nvd import NVDSource
    from datetime import datetime, timedelta
    nvd = NVDSource()
    try:
        cves = await nvd.fetch_recent(since=datetime.utcnow() - timedelta(days=1))
        results.append({"step": "fetch", "status": "ok", "count": len(cves)})
    except Exception as e:
        results.append({"step": "fetch", "status": "error", "error": str(e)})
        cves = []

    # Step 3: Filter test
    from app.engine.filter_engine import filter_cves
    from app.engine.rule_loader import get_rules

    rules = [r for r in get_rules() if r.get("enabled", True)]
    matches = filter_cves(cves, rules) if rules else []
    results.append({"step": "filter", "status": "ok", "matches": len(matches), "rules": len(rules)})

    # Step 4: Database connectivity
    from app.models.cve import CVE
    from sqlalchemy import func, select
    total = (await db.execute(select(func.count()).select_from(CVE))).scalar() or 0
    results.append({"step": "database", "status": "ok", "total_cves": total})

    # Step 5: Redis connectivity
    import redis.asyncio as aioredis
    from app.config import settings
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        await r.aclose()
        results.append({"step": "redis", "status": "ok"})
    except Exception as e:
        results.append({"step": "redis", "status": "error", "error": str(e)})

    all_ok = all(r.get("status") == "ok" or r.get("status") == "sent" for r in results)

    return {
        "overall": "pass" if all_ok else "partial",
        "steps": results,
    }


@router.get("/email-routing")
async def get_email_routing():
    """Show current email routing configuration (no secrets exposed)."""
    from app.config import settings

    def _mask_emails(emails: list) -> list:
        """Show first/last char of each email for verification without full exposure."""
        masked = []
        for e in emails:
            if "@" in e:
                local, domain = e.split("@", 1)
                if len(local) > 2:
                    masked.append(f"{local[0]}***{local[-1]}@{domain}")
                else:
                    masked.append(f"{local[0]}***@{domain}")
            else:
                masked.append("***")
        return masked

    return {
        "smtp_configured": bool(settings.smtp_host and settings.smtp_user),
        "smtp_from": settings.smtp_from or settings.smtp_user or "(not set)",
        "routing": {
            "alert_emails": {
                "description": "CVE alert emails (individual CVE matches)",
                "recipients": _mask_emails(settings.recipient_list),
                "count": len(settings.recipient_list),
            },
            "scan_summary_with_alerts": {
                "description": "Scan summaries with >0 alerts (actionable)",
                "recipients": _mask_emails(settings.recipient_list),
                "count": len(settings.recipient_list),
            },
            "scan_summary_no_alerts": {
                "description": "Scan summaries with 0 alerts (debug/admin)",
                "recipients": _mask_emails(settings.scan_recipient_list),
                "count": len(settings.scan_recipient_list),
            },
            "health_report": {
                "description": "Daily health check emails",
                "recipients": _mask_emails(settings.health_recipient_list),
                "count": len(settings.health_recipient_list),
            },
            "webhook_contact": {
                "description": "Contact email in CRM/webhook payloads",
                "email": settings.webhook_email_address or "(not set)",
            },
        },
    }
