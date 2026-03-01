"""Filter rules API routes – read-only (Wazuh-style file-based rules).

Rules are loaded from abusecve_filters.yaml on disk.
Edit the file directly on the server and call POST /api/filters/reload.
"""

from __future__ import annotations

import logging
import time
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from sqlalchemy import select as sa_select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.engine.rule_loader import get_rules, get_rule_by_id, reload_rules

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/filters", tags=["Filters"])


class TestFilterRequest(BaseModel):
    """Test a rule against all CVEs in the database."""
    rule_id: Optional[int] = None
    pql: Optional[str] = None
    send_test_alert: bool = False
    limit: int = Field(default=0, ge=0, description="Max CVEs to return (0 = all)")


# ══════════════════════════════════════════════════════════
# STATIC ROUTES — must be defined BEFORE /{rule_id}
# ══════════════════════════════════════════════════════════

@router.get("")
async def list_filters():
    """List all rules loaded from the config file."""
    rules = get_rules()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "enabled": r["enabled"],
            "alert_on_modified": r["alert_on_modified"],
            "description": r["description"],
            "pql": r.get("pql", ""),
        }
        for r in rules
    ]


@router.post("/reload")
async def reload_filter_rules():
    """Hot-reload rules from disk."""
    rules = reload_rules()
    enabled = sum(1 for r in rules if r["enabled"])
    return {
        "message": f"Reloaded {len(rules)} rules ({enabled} enabled)",
        "total": len(rules),
        "enabled": enabled,
    }


@router.get("/query-help")
async def get_query_help():
    """Return PQL syntax reference."""
    return {
        "pql_syntax": [
            {"syntax": "field:value", "description": "Contains match (case-insensitive)", "example": "vendor:fortinet"},
            {"syntax": 'field:"multi word"', "description": "Contains match with spaces", "example": 'description:"buffer overflow"'},
            {"syntax": "field:=value", "description": "Exact match", "example": "severity:=CRITICAL"},
            {"syntax": "field:~pattern", "description": "Regex match (quote if pattern has parens)", "example": 'vendor:~"(?i)forti(net)?"'},
            {"syntax": "field:!value", "description": "Not-contains", "example": "description:!deprecated"},
            {"syntax": "field:>=N", "description": "Numeric comparison (also >, <, <=)", "example": "cvss:>=7.0"},
            {"syntax": "field:blank", "description": "Field is null or empty", "example": "cvss:blank"},
            {"syntax": "field:not_blank", "description": "Field has a value", "example": "cvss:not_blank"},
            {"syntax": "field:A,B", "description": "Comma-separated OR of exact values", "example": "severity:HIGH,CRITICAL"},
            {"syntax": "kev:true", "description": "Boolean shorthand", "example": "kev:true"},
            {"syntax": "AND", "description": "Boolean AND (implicit between adjacent terms)", "example": "vendor:forti cvss:>=7"},
            {"syntax": "OR", "description": "Boolean OR", "example": "vendor:forti OR vendor:microsoft"},
            {"syntax": "NOT", "description": "Boolean NOT (prefix)", "example": "NOT severity:LOW"},
            {"syntax": "( )", "description": "Grouping", "example": "(vendor:forti OR vendor:wazuh) AND cvss:>=7"},
        ],
        "field_aliases": {
            "id/cve/cveid": "cve_id",
            "desc/descr": "description",
            "sev/level": "severity",
            "cvss/score": "cvss_score",
            "kev": "kev_flag",
            "pub/published": "published_date",
            "mod/modified": "modified_date",
            "vec/vector": "cvss_vector",
        },
        "fields": [
            "cve_id", "vendor", "product", "description", "severity",
            "cvss_score", "cvss_vector", "source", "sources",
            "published_date", "modified_date", "kev_flag",
            "cpe_names", "references", "weaknesses", "affected_products",
        ],
    }


@router.post("/test")
async def test_filter_rule(data: TestFilterRequest, db: AsyncSession = Depends(get_db)):
    """Test a rule (by ID or ad-hoc PQL) against all CVEs in the database."""
    from app.engine.filter_engine import match_cve_against_rule
    from app.engine.sources.base import NormalizedCVE
    from app.engine.query_engine import parse_pql_to_conditions
    from app.models.cve import CVE

    t_start = time.monotonic()

    # Build rule dict to test
    rule_dict = None

    if data.rule_id is not None:
        rule = get_rule_by_id(data.rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail=f"Rule ID {data.rule_id} not found in config file")
        rule_dict = rule
    elif data.pql:
        try:
            parsed = parse_pql_to_conditions(data.pql)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"PQL parse error: {exc}")
        rule_dict = {
            "id": 0,
            "name": "Ad-hoc PQL Test",
            "enabled": True,
            "pql": data.pql,
            "_parsed_conditions": parsed,
        }
    else:
        raise HTTPException(status_code=400, detail="Provide rule_id or pql")

    # Count total CVEs
    total_count_result = await db.execute(sa_select(func.count()).select_from(CVE))
    total_cves = total_count_result.scalar() or 0

    if total_cves == 0:
        return {
            "status": "no_data",
            "message": "No CVEs in database. Initialize DB first.",
            "total_tested": 0,
            "matches": 0,
            "matched_cves": [],
            "elapsed_seconds": 0,
        }

    # Scan all CVEs in batches
    BATCH = 2000
    matched_cves = []
    offset = 0

    while True:
        batch_result = await db.execute(
            sa_select(CVE).order_by(CVE.id).offset(offset).limit(BATCH)
        )
        batch = batch_result.scalars().all()
        if not batch:
            break

        for c in batch:
            try:
                cve = NormalizedCVE(
                    cve_id=c.cve_id,
                    vendor=c.vendor,
                    product=c.product,
                    description=c.description,
                    severity=c.severity,
                    cvss_score=c.cvss_score,
                    cvss_vector=c.cvss_vector,
                    source=c.source,
                    sources=c.sources or [],
                    published_date=c.published_date,
                    modified_date=c.modified_date,
                    kev_flag=c.kev_flag,
                    cpe_names=c.cpe_names if isinstance(c.cpe_names, list) else [],
                    references=c.references if isinstance(c.references, list) else [],
                    weaknesses=c.weaknesses if isinstance(c.weaknesses, list) else [],
                    affected_products=c.affected_products if isinstance(c.affected_products, list) else [],
                )
                if match_cve_against_rule(cve, rule_dict):
                    matched_cves.append({
                        "cve_id": c.cve_id,
                        "vendor": c.vendor,
                        "product": c.product,
                        "severity": c.severity,
                        "cvss_score": c.cvss_score,
                        "source": c.source,
                        "kev_flag": c.kev_flag,
                        "description": (c.description or "")[:300],
                        "published_date": c.published_date.isoformat() if c.published_date else None,
                    })
            except Exception as cve_err:
                logger.warning(f"Skipping CVE {getattr(c, 'cve_id', '?')} during test: {cve_err}")
                continue

        offset += BATCH
        if len(batch) < BATCH:
            break

    elapsed = round(time.monotonic() - t_start, 2)
    returned = matched_cves[:data.limit] if data.limit else matched_cves

    # Optional test alert
    if data.send_test_alert and matched_cves:
        try:
            from app.services.smtp_service import send_cve_alert
            cve_dict = matched_cves[0].copy()
            await send_cve_alert(cve_dict, rule_name=f"[TEST] {rule_dict['name']}")
            logger.info(f"Test alert sent for {cve_dict['cve_id']}")
        except Exception as exc:
            logger.error(f"Test alert failed: {exc}", exc_info=True)

    return {
        "status": "ok",
        "rule_name": rule_dict["name"],
        "rule_id": rule_dict.get("id"),
        "total_tested": total_cves,
        "matches": len(matched_cves),
        "returned": len(returned),
        "elapsed_seconds": elapsed,
        "matched_cves": returned,
    }


# ══════════════════════════════════════════════════════════
# PARAMETERIZED ROUTES — must be AFTER all static routes
# ══════════════════════════════════════════════════════════

@router.get("/{rule_id}")
async def get_filter(rule_id: int):
    """Get a single rule by its numeric ID."""
    rule = get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule ID {rule_id} not found")
    return {
        "id": rule["id"],
        "name": rule["name"],
        "enabled": rule["enabled"],
        "alert_on_modified": rule["alert_on_modified"],
        "description": rule["description"],
        "pql": rule.get("pql", ""),
    }
