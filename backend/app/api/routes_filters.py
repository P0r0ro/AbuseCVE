"""Filter rules API routes – CRUD, YAML import/export, test filter."""

from __future__ import annotations

import io
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from sqlalchemy import select, delete, func
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
    """Test a filter rule against ALL CVEs in DB."""
    filter_id: Optional[int] = None  # Test an existing saved filter by ID
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
    pql_query: Optional[str] = None
    severity_mapping: Optional[Dict[str, Any]] = None
    include_unknown: bool = False
    send_test_alert: bool = False
    limit: int = Field(default=0, ge=0, description="Max CVEs to return (0 = all)")


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
    """Test a filter rule against ALL CVEs in the database."""
    import time
    from app.engine.filter_engine import match_cve_against_rule
    from app.engine.sources.base import NormalizedCVE
    from app.models.cve import CVE
    from sqlalchemy import select as sa_select

    t_start = time.monotonic()

    # If filter_id provided, load rule from DB
    rule_dict = None
    if data.filter_id:
        result = await db.execute(sa_select(FilterRule).where(FilterRule.id == data.filter_id))
        saved = result.scalar_one_or_none()
        if not saved:
            raise HTTPException(status_code=404, detail=f"Filter rule #{data.filter_id} not found")
        rule_dict = {
            "id": saved.id,
            "name": saved.name,
            "vendor": saved.vendor,
            "products": saved.products or [],
            "enabled": True,
            "min_cvss": saved.min_cvss,
            "max_cvss": saved.max_cvss,
            "severity_filter": saved.severity_filter or [],
            "keywords_include": saved.keywords_include or [],
            "keywords_exclude": saved.keywords_exclude or [],
            "cpe_vendor": saved.cpe_vendor,
            "alert_on_modified": saved.alert_on_modified,
            "conditions": saved.conditions,
            "pql_query": getattr(saved, 'pql_query', None),
            "severity_mapping": getattr(saved, 'severity_mapping', None),
            "include_unknown": getattr(saved, 'include_unknown', False),
        }
    else:
        rule_dict = {
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
            "pql_query": data.pql_query,
            "severity_mapping": data.severity_mapping,
            "include_unknown": data.include_unknown,
        }

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

    # Scan ALL CVEs in batches
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
                cpe_names=c.cpe_names or [],
                references=c.references or [],
                weaknesses=c.weaknesses or [],
                affected_products=c.affected_products or [],
            )
            match = match_cve_against_rule(cve, rule_dict)
            if match:
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

        offset += BATCH
        if len(batch) < BATCH:
            break

    elapsed = round(time.monotonic() - t_start, 2)

    # Optional: apply return limit
    returned = matched_cves[:data.limit] if data.limit else matched_cves

    # Send test alert if requested
    if data.send_test_alert and matched_cves:
        try:
            from app.services.smtp_service import send_cve_alert
            cve_dict = matched_cves[0].copy()
            await send_cve_alert(cve_dict, rule_name=f"[TEST] {rule_dict['name']}")
            logger.info(f"Test alert sent for {cve_dict['cve_id']}")
        except Exception as e:
            logger.error(f"Test alert failed: {e}", exc_info=True)

    return {
        "status": "ok",
        "rule_name": rule_dict["name"],
        "total_tested": total_cves,
        "matches": len(matched_cves),
        "returned": len(returned),
        "elapsed_seconds": elapsed,
        "matched_cves": returned,
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
