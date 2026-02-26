"""Filter rules API routes – CRUD, YAML import/export, test filter."""

from __future__ import annotations

import io
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.filter_rule import FilterRule

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/filters", tags=["Filters"])


class FilterRuleCreate(BaseModel):
    name: str
    vendor: Optional[str] = None
    products: List[str] = []
    enabled: bool = True
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    severity_filter: List[str] = []
    keywords_include: List[str] = []
    keywords_exclude: List[str] = []
    cpe_vendor: Optional[str] = None
    description: Optional[str] = None
    alert_on_modified: bool = False
    conditions: Optional[Dict[str, Any]] = None


class FilterRuleUpdate(BaseModel):
    name: Optional[str] = None
    vendor: Optional[str] = None
    products: Optional[List[str]] = None
    enabled: Optional[bool] = None
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    severity_filter: Optional[List[str]] = None
    keywords_include: Optional[List[str]] = None
    keywords_exclude: Optional[List[str]] = None
    cpe_vendor: Optional[str] = None
    description: Optional[str] = None
    alert_on_modified: Optional[bool] = None
    conditions: Optional[Dict[str, Any]] = None


class TestFilterRequest(BaseModel):
    """Test a filter rule against current DB."""
    name: str = "Test Rule"
    vendor: Optional[str] = None
    products: List[str] = []
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    severity_filter: List[str] = []
    keywords_include: List[str] = []
    keywords_exclude: List[str] = []
    cpe_vendor: Optional[str] = None
    alert_on_modified: bool = False
    conditions: Optional[Dict[str, Any]] = None
    send_test_alert: bool = False


# ══════════════════════════════════════════════════════════
# STATIC ROUTES — must be defined BEFORE /{filter_id}
# ══════════════════════════════════════════════════════════

@router.get("")
async def list_filters(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).order_by(FilterRule.created_at.desc()))
    filters = result.scalars().all()
    return [f.to_dict() for f in filters]


@router.post("", status_code=201)
async def create_filter(data: FilterRuleCreate, db: AsyncSession = Depends(get_db)):
    rule = FilterRule(
        name=data.name,
        vendor=data.vendor,
        products=data.products,
        enabled=data.enabled,
        min_cvss=data.min_cvss,
        max_cvss=data.max_cvss,
        severity_filter=data.severity_filter,
        keywords_include=data.keywords_include,
        keywords_exclude=data.keywords_exclude,
        cpe_vendor=data.cpe_vendor,
        description=data.description,
        alert_on_modified=data.alert_on_modified,
        conditions=data.conditions,
    )
    db.add(rule)
    await db.flush()
    return rule.to_dict()


# ── Query Language Help ──────────────────────────────────
@router.get("/query-help")
async def get_query_help():
    """Return query language documentation."""
    return {
        "operators": [
            {"name": "equal", "description": "Exact match (case-insensitive). Supports * and ? wildcards.", "example": '{"field": "vendor", "operator": "equal", "value": "forti*"}'},
            {"name": "not_equal", "description": "Not equal (case-insensitive). Supports * and ? wildcards.", "example": '{"field": "vendor", "operator": "not_equal", "value": "microsoft"}'},
            {"name": "contains", "description": "Substring match. ? wildcard allowed, * NOT allowed.", "example": '{"field": "description", "operator": "contains", "value": "buffer overflow"}'},
            {"name": "not_contains", "description": "Substring exclusion. ? wildcard allowed, * NOT allowed.", "example": '{"field": "description", "operator": "not_contains", "value": "low risk"}'},
            {"name": "blank", "description": "Field is null or empty string.", "example": '{"field": "cvss_score", "operator": "blank"}'},
            {"name": "not_blank", "description": "Field has a non-empty value.", "example": '{"field": "cvss_score", "operator": "not_blank"}'},
            {"name": "starts_with", "description": "Value starts with pattern. Supports wildcards.", "example": '{"field": "cve_id", "operator": "starts_with", "value": "CVE-2024"}'},
            {"name": "ends_with", "description": "Value ends with pattern. Supports wildcards.", "example": '{"field": "vendor", "operator": "ends_with", "value": "net"}'},
            {"name": "not_starts_with", "description": "Value does NOT start with pattern.", "example": '{"field": "cve_id", "operator": "not_starts_with", "value": "CVE-2020"}'},
            {"name": "not_ends_with", "description": "Value does NOT end with pattern.", "example": '{"field": "product", "operator": "not_ends_with", "value": "legacy"}'},
            {"name": "regex", "description": "PCRE2-compatible regular expression match.", "example": '{"field": "description", "operator": "regex", "value": "(?i)remote\\\\s+code\\\\s+execution"}'},
            {"name": "gte", "description": "Greater than or equal (numeric).", "example": '{"field": "cvss_score", "operator": "gte", "value": 7.0}'},
            {"name": "lte", "description": "Less than or equal (numeric).", "example": '{"field": "cvss_score", "operator": "lte", "value": 9.0}'},
            {"name": "gt", "description": "Greater than (numeric).", "example": '{"field": "cvss_score", "operator": "gt", "value": 8.0}'},
            {"name": "lt", "description": "Less than (numeric).", "example": '{"field": "cvss_score", "operator": "lt", "value": 4.0}'},
            {"name": "similarity", "description": "Fuzzy string similarity match (0.0-1.0 threshold).", "example": '{"field": "vendor", "operator": "similarity", "value": "fortnet"}'},
        ],
        "wildcards": {
            "*": "Matches any number of characters. Available for: equal, not_equal, starts_with, ends_with, not_starts_with, not_ends_with. NOT available for contains/not_contains.",
            "?": "Matches exactly one character. Examples: p?ul matches paul/poul. Available for ALL operators.",
        },
        "nesting": {
            "description": "Combine conditions with AND/OR/NOT logic to any depth.",
            "example": {
                "logic": "AND",
                "conditions": [
                    {"field": "vendor", "operator": "contains", "value": "forti"},
                    {
                        "logic": "OR",
                        "conditions": [
                            {"field": "severity", "operator": "equal", "value": "CRITICAL"},
                            {"field": "cvss_score", "operator": "gte", "value": 9.0},
                        ],
                    },
                ],
            },
        },
        "fields": [
            "cve_id", "vendor", "product", "description", "severity",
            "cvss_score", "cvss_vector", "source", "sources",
            "published_date", "modified_date", "kev_flag",
            "cpe_names", "references", "weaknesses", "affected_products",
        ],
        "case_sensitivity": "All operators are case-insensitive by default. Set 'case_sensitive': true for exact case matching.",
    }


# ── Test Filter ──────────────────────────────────────────
@router.post("/test")
async def test_filter_rule(data: TestFilterRequest, db: AsyncSession = Depends(get_db)):
    """Test a filter rule against the database and optionally send a test alert."""
    from app.engine.filter_engine import filter_cves
    from app.engine.sources.base import NormalizedCVE
    from app.models.cve import CVE
    from datetime import datetime

    # Get recent CVEs from DB
    result = await db.execute(
        select(CVE).order_by(CVE.published_date.desc()).limit(500)
    )
    db_cves = result.scalars().all()

    if not db_cves:
        return {
            "status": "no_data",
            "message": "No CVEs in database to test against. Initialize DB first.",
            "matches": [],
        }

    # Convert DB records to NormalizedCVE for filter engine
    cves = []
    for c in db_cves:
        cves.append(NormalizedCVE(
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
            cpe_names=c.cpe_names or [],
            references=c.references or [],
            weaknesses=c.weaknesses or [],
            affected_products=c.affected_products or [],
        ))

    # Build test rule
    rule = {
        "id": 0,
        "name": data.name,
        "vendor": data.vendor,
        "products": data.products,
        "enabled": True,
        "min_cvss": data.min_cvss,
        "max_cvss": data.max_cvss,
        "severity_filter": data.severity_filter,
        "keywords_include": data.keywords_include,
        "keywords_exclude": data.keywords_exclude,
        "cpe_vendor": data.cpe_vendor,
        "alert_on_modified": data.alert_on_modified,
        "conditions": data.conditions,
    }

    matches = filter_cves(cves, [rule])

    # Send test alert if requested and matches found
    if data.send_test_alert and matches:
        try:
            from app.services.smtp_service import send_cve_alert
            first_match = matches[0].cve
            cve_dict = {
                "cve_id": first_match.cve_id,
                "vendor": first_match.vendor,
                "product": first_match.product,
                "description": first_match.description,
                "severity": first_match.severity,
                "cvss_score": first_match.cvss_score,
                "source": first_match.source,
                "kev_flag": first_match.kev_flag,
            }
            email_result = await send_cve_alert(cve_dict, rule_name=f"[TEST] {data.name}")
            logger.info(f"Test alert sent: {email_result}")
        except Exception as e:
            logger.error(f"Test alert send failed: {e}", exc_info=True)

    return {
        "status": "ok",
        "total_tested": len(cves),
        "matches": len(matches),
        "matched_cves": [
            {
                "cve_id": m.cve.cve_id,
                "vendor": m.cve.vendor,
                "product": m.cve.product,
                "severity": m.cve.severity,
                "cvss_score": m.cve.cvss_score,
            }
            for m in matches[:20]
        ],
    }


# ── YAML Export ──────────────────────────────────────────
@router.get("/export/yaml")
async def export_filters_yaml(db: AsyncSession = Depends(get_db)):
    """Export all filter rules as a YAML file."""
    try:
        import yaml
    except ImportError:
        # Fallback to JSON-based YAML-like format
        result = await db.execute(select(FilterRule).order_by(FilterRule.created_at.desc()))
        rules = [r.to_dict() for r in result.scalars().all()]
        for rule in rules:
            rule.pop("id", None)
            rule.pop("created_at", None)
            rule.pop("updated_at", None)
        content = json.dumps({"filter_rules": rules}, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=abusecve_filters.json"},
        )

    result = await db.execute(select(FilterRule).order_by(FilterRule.created_at.desc()))
    rules = []
    for r in result.scalars().all():
        rule_dict = r.to_dict()
        rule_dict.pop("id", None)
        rule_dict.pop("created_at", None)
        rule_dict.pop("updated_at", None)
        rules.append(rule_dict)

    yaml_content = yaml.dump(
        {"filter_rules": rules},
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )

    return Response(
        content=yaml_content,
        media_type="application/x-yaml",
        headers={"Content-Disposition": "attachment; filename=abusecve_filters.yaml"},
    )


# ── YAML Import ──────────────────────────────────────────
@router.post("/import/yaml")
async def import_filters_yaml(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Import filter rules from a YAML or JSON file."""
    try:
        content = await file.read()
        content_str = content.decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to read uploaded file: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    logger.info(f"Import YAML: received {len(content_str)} bytes from '{file.filename}'")

    rules_data = None

    # Try YAML first
    try:
        import yaml
        data = yaml.safe_load(content_str)
        if isinstance(data, dict):
            rules_data = data.get("filter_rules", [])
            logger.info(f"Parsed YAML: found {len(rules_data)} rules")
    except ImportError:
        logger.warning("PyYAML not installed, falling back to JSON")
    except Exception as e:
        logger.warning(f"YAML parse failed: {e}, trying JSON")

    # Fallback to JSON
    if rules_data is None:
        try:
            data = json.loads(content_str)
            if isinstance(data, dict):
                rules_data = data.get("filter_rules", [])
            logger.info(f"Parsed JSON: found {len(rules_data or [])} rules")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML/JSON file: {e}")

    if not rules_data:
        raise HTTPException(status_code=400, detail="No filter_rules found in file")

    imported = 0
    errors = []
    for idx, rule_data in enumerate(rules_data):
        try:
            name = rule_data.get("name")
            if not name:
                errors.append(f"Rule {idx}: missing name")
                continue

            rule = FilterRule(
                name=name,
                vendor=rule_data.get("vendor"),
                products=rule_data.get("products", []),
                enabled=rule_data.get("enabled", True),
                min_cvss=rule_data.get("min_cvss"),
                max_cvss=rule_data.get("max_cvss"),
                severity_filter=rule_data.get("severity_filter", []),
                keywords_include=rule_data.get("keywords_include", []),
                keywords_exclude=rule_data.get("keywords_exclude", []),
                cpe_vendor=rule_data.get("cpe_vendor"),
                description=rule_data.get("description"),
                alert_on_modified=rule_data.get("alert_on_modified", False),
                conditions=rule_data.get("conditions"),
            )
            db.add(rule)
            imported += 1
        except Exception as e:
            logger.error(f"Rule {idx} import error: {e}", exc_info=True)
            errors.append(f"Rule {idx} ({rule_data.get('name', '?')}): {e}")

    try:
        await db.commit()
        logger.info(f"Import complete: {imported} rules imported, {len(errors)} errors")
    except Exception as e:
        logger.error(f"DB commit failed during import: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    return {
        "message": f"Imported {imported} filter rules",
        "imported": imported,
        "errors": errors,
    }


# ══════════════════════════════════════════════════════════
# PARAMETERIZED ROUTES — must be AFTER all static routes
# ══════════════════════════════════════════════════════════

@router.get("/{filter_id}")
async def get_filter(filter_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")
    return rule.to_dict()


@router.put("/{filter_id}")
async def update_filter(filter_id: int, data: FilterRuleUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(rule, key, value)
    await db.flush()
    return rule.to_dict()


@router.delete("/{filter_id}")
async def delete_filter(filter_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")
    await db.delete(rule)
    await db.flush()
    return {"message": "Filter rule deleted"}


@router.post("/{filter_id}/toggle")
async def toggle_filter(filter_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")
    rule.enabled = not rule.enabled
    await db.flush()
    return rule.to_dict()
