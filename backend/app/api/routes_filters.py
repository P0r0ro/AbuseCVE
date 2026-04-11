"""Filter rules API routes – file-based rules (Wazuh-style).

Rules are loaded from abusecve_filters.yaml on disk.
Edit the file directly on the server and call POST /api/filters/reload.
Includes the Rule Refinement Wizard endpoint for FP mitigation from Alerts.
"""

from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Optional
from sqlalchemy import select as sa_select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.engine.rule_loader import get_rules, get_rule_by_id, reload_rules, get_rules_path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/filters", tags=["Filters"])


class TestFilterRequest(BaseModel):
    """Test a rule against all CVEs in the database."""
    rule_id: Optional[int] = None
    pql: Optional[str] = None
    send_test_alert: bool = False
    limit: int = Field(default=0, ge=0, description="Max CVEs to return (0 = all)")


class Negation(BaseModel):
    """A single negation criterion for the refinement wizard."""
    type: str  # "keyword", "product", "version", "cvss"
    value: str  # The keyword/product/version string, or CVSS threshold


class RefineFilterRequest(BaseModel):
    """Refine a rule by appending negation logic to its PQL."""
    rule_id: int
    negations: List[Negation]
    preview_only: bool = Field(default=False, description="If true, return before/after without saving")


class CreateRuleRequest(BaseModel):
    """Append a new rule to abusecve_filters.yaml from the Rule Wizard."""
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    pql: str = Field(..., min_length=1)
    enabled: bool = True
    alert_on_modified: bool = False
    id: Optional[int] = None  # auto-assigned if omitted


class UpdateRuleRequest(BaseModel):
    """Update an existing rule in abusecve_filters.yaml."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    pql: Optional[str] = Field(default=None, min_length=1)
    enabled: Optional[bool] = None
    alert_on_modified: Optional[bool] = None


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

    # Optional test alert — sends email regardless of match count
    test_alert_result = None
    if data.send_test_alert:
        try:
            from app.services.smtp_service import send_filter_test_email
            test_alert_result = await send_filter_test_email(
                rule_name=rule_dict["name"],
                rule_id=rule_dict.get("id"),
                pql=rule_dict.get("pql", data.pql or ""),
                total_tested=total_cves,
                match_count=len(matched_cves),
                elapsed=elapsed,
                sample_cves=matched_cves[:10],
            )
            logger.info(f"Filter test email sent: {test_alert_result}")
        except Exception as exc:
            logger.error(f"Test alert failed: {exc}", exc_info=True)
            test_alert_result = {"status": "failed", "error": str(exc)}

    return {
        "status": "ok",
        "rule_name": rule_dict["name"],
        "rule_id": rule_dict.get("id"),
        "total_tested": total_cves,
        "matches": len(matched_cves),
        "returned": len(returned),
        "elapsed_seconds": elapsed,
        "matched_cves": returned,
        **({"test_alert": test_alert_result} if test_alert_result else {}),
    }


@router.post("/refine")
async def refine_filter_rule(data: RefineFilterRequest):
    """Refine a rule by appending AND NOT negation logic to its PQL.

    Used by the Rule Refinement Wizard to mitigate false positives.
    Creates a backup of the YAML before writing. If validation fails,
    the backup is restored automatically.
    """
    from app.engine.query_engine import parse_pql_to_conditions

    # 1. Find the rule
    rule = get_rule_by_id(data.rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule ID {data.rule_id} not found")

    original_pql = rule.get("pql", "").strip()
    if not original_pql:
        raise HTTPException(status_code=400, detail="Rule has no PQL to refine")

    if not data.negations:
        raise HTTPException(status_code=400, detail="No negation criteria provided")

    # 2. Build the negation clause(s)
    negation_parts = []
    for neg in data.negations:
        val = neg.value.strip()
        if not val:
            continue
        if neg.type == "keyword":
            negation_parts.append(f'description:"{val}"')
        elif neg.type == "product":
            negation_parts.append(f'product:"{val}"')
        elif neg.type == "version":
            negation_parts.append(f'description:"{val}"')
        elif neg.type == "cvss":
            # CVSS threshold: keep only CVEs >= threshold (not a NOT, it's a floor)
            pass
        else:
            continue

    # Build the new PQL
    new_pql = original_pql

    # Append NOT clauses
    if negation_parts:
        not_clause = " OR ".join(negation_parts)
        if len(negation_parts) > 1:
            not_clause = f"({not_clause})"
        new_pql = f"({new_pql}) AND NOT ({not_clause})"

    # Append CVSS threshold (if any)
    cvss_negations = [n for n in data.negations if n.type == "cvss"]
    if cvss_negations:
        threshold = cvss_negations[0].value.strip()
        try:
            float(threshold)
            new_pql = f"({new_pql}) AND (cvss:>={threshold})"
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid CVSS threshold: {threshold}")

    # 3. Validate the new PQL parses correctly
    try:
        parse_pql_to_conditions(new_pql)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Generated PQL is invalid: {exc}")

    # 4. Preview mode — return before/after without saving
    if data.preview_only:
        return {
            "status": "preview",
            "rule_id": data.rule_id,
            "rule_name": rule["name"],
            "original_pql": original_pql,
            "refined_pql": new_pql,
        }

    # 5. Write to YAML (using ruamel.yaml to preserve comments)
    rules_path = get_rules_path()
    if not rules_path.exists():
        raise HTTPException(status_code=500, detail=f"Rules file not found: {rules_path}")

    # Create backup
    backup_path = rules_path.with_suffix(
        f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    shutil.copy2(rules_path, backup_path)
    logger.info(f"Refine: backed up rules to {backup_path}")

    try:
        from ruamel.yaml import YAML

        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.width = 4096  # prevent line wrapping

        with open(rules_path, "r", encoding="utf-8") as fh:
            doc = yaml.load(fh)

        # Find and update the rule in the YAML document
        rules_list = doc.get("rules") or doc.get("filter_rules") or []
        updated = False
        for r in rules_list:
            if r.get("id") == data.rule_id:
                r["pql"] = new_pql
                updated = True
                break

        if not updated:
            raise HTTPException(
                status_code=404,
                detail=f"Rule ID {data.rule_id} not found in YAML file"
            )

        with open(rules_path, "w", encoding="utf-8") as fh:
            yaml.dump(doc, fh)

        logger.info(f"Refine: updated rule {data.rule_id} PQL in {rules_path}")

    except HTTPException:
        raise
    except Exception as exc:
        # Restore backup on any write error
        logger.error(f"Refine: write failed, restoring backup: {exc}")
        shutil.copy2(backup_path, rules_path)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update YAML file: {exc}. Backup restored."
        )

    # 6. Validate the saved file loads correctly
    try:
        reloaded = reload_rules()
        reloaded_rule = None
        for r in reloaded:
            if r["id"] == data.rule_id:
                reloaded_rule = r
                break

        if reloaded_rule and not reloaded_rule.get("enabled"):
            # Rule got disabled during reload = PQL parse error
            logger.error("Refine: reloaded rule is disabled (PQL error), reverting")
            shutil.copy2(backup_path, rules_path)
            reload_rules()
            raise HTTPException(
                status_code=500,
                detail="Rule was disabled after reload (PQL error). Reverted to backup."
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Refine: reload failed, restoring backup: {exc}")
        shutil.copy2(backup_path, rules_path)
        reload_rules()
        raise HTTPException(
            status_code=500,
            detail=f"Reload failed after update: {exc}. Backup restored."
        )

    logger.info(f"Refine: rule {data.rule_id} successfully refined and reloaded")
    return {
        "status": "ok",
        "rule_id": data.rule_id,
        "rule_name": rule["name"],
        "original_pql": original_pql,
        "refined_pql": new_pql,
        "backup_path": str(backup_path),
    }


@router.post("/create")
async def create_rule(data: CreateRuleRequest, request: Request):
    """Append a new rule to abusecve_filters.yaml.

    Used by the Rule Wizard and the Advanced Mode editor to persist
    analyst-authored rules directly to disk. Validates PQL before writing,
    creates a timestamped backup, and hot-reloads on success.

    RBAC is enforced centrally in the RBAC middleware based on the
    ``soc_rule_create`` toggle.
    """
    from app.engine.query_engine import parse_pql_to_conditions

    pql = data.pql.strip()
    if not pql:
        raise HTTPException(status_code=400, detail="PQL cannot be empty")

    # 1. Validate the PQL parses
    try:
        parse_pql_to_conditions(pql)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid PQL: {exc}")

    rules_path = get_rules_path()
    if not rules_path.exists():
        raise HTTPException(status_code=500, detail=f"Rules file not found: {rules_path}")

    # 2. Backup
    backup_path = rules_path.with_suffix(
        f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    shutil.copy2(rules_path, backup_path)

    try:
        from ruamel.yaml import YAML
        from ruamel.yaml.scalarstring import LiteralScalarString

        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.width = 4096

        with open(rules_path, "r", encoding="utf-8") as fh:
            doc = yaml.load(fh)

        rules_list = doc.get("rules") or doc.get("filter_rules") or []

        # 3. Assign a new ID if not provided — use max existing + 1
        existing_ids = {int(r.get("id", 0)) for r in rules_list if r.get("id") is not None}
        new_id = data.id if data.id is not None else (max(existing_ids) + 1 if existing_ids else 1001)
        if new_id in existing_ids:
            raise HTTPException(status_code=409, detail=f"Rule ID {new_id} already exists")

        # 4. Build the new rule entry
        new_rule = {
            "id": new_id,
            "name": data.name,
            "enabled": data.enabled,
            "alert_on_modified": data.alert_on_modified,
            "description": data.description or "",
            "pql": LiteralScalarString(pql) if "\n" in pql else pql,
        }

        rules_list.append(new_rule)
        if "rules" in doc:
            doc["rules"] = rules_list
        else:
            doc["filter_rules"] = rules_list

        with open(rules_path, "w", encoding="utf-8") as fh:
            yaml.dump(doc, fh)

        logger.info(f"Created rule {new_id} ({data.name}) in {rules_path}")

    except HTTPException:
        shutil.copy2(backup_path, rules_path)
        raise
    except Exception as exc:
        logger.error(f"Create rule failed: {exc}, restoring backup")
        shutil.copy2(backup_path, rules_path)
        raise HTTPException(status_code=500, detail=f"Failed to write YAML: {exc}")

    # 5. Hot-reload
    try:
        reload_rules()
    except Exception as exc:
        shutil.copy2(backup_path, rules_path)
        reload_rules()
        raise HTTPException(status_code=500, detail=f"Reload failed: {exc}. Backup restored.")

    return {
        "status": "ok",
        "rule_id": new_id,
        "name": data.name,
        "pql": pql,
        "backup_path": str(backup_path),
    }


@router.get("/autocomplete")
async def pql_autocomplete():
    """Return the keyword/operator list used by PQL auto-completion dropdowns."""
    return {
        "keywords": [
            "vendor:", "product:", "severity:", "cvss:", "description:",
            "kev:", "cve_id:", "source:", "cvss_vector:", "published_date:",
            "modified_date:", "cpe_names:", "references:", "weaknesses:",
            "affected_products:",
        ],
        "values": {
            "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "kev": ["true", "false"],
            "source": ["NVD", "MITRE", "CISA_KEV", "REDHAT"],
        },
        "operators": ["AND", "OR", "NOT", "(", ")"],
        "comparators": [":>=", ":>", ":<=", ":<", ":=", ":~", ":!"],
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


@router.put("/{rule_id}")
async def update_rule(rule_id: int, data: UpdateRuleRequest):
    """Update an existing rule in abusecve_filters.yaml.

    Only fields provided in the request body are modified. Validates
    PQL before writing, creates a timestamped backup, and hot-reloads
    on success. Restores the backup if the reload fails.

    RBAC is enforced centrally in the middleware via the
    ``soc_rule_edit`` toggle.
    """
    from app.engine.query_engine import parse_pql_to_conditions

    rule = get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule ID {rule_id} not found")

    # Validate PQL if provided
    new_pql = None
    if data.pql is not None:
        new_pql = data.pql.strip()
        if not new_pql:
            raise HTTPException(status_code=400, detail="PQL cannot be empty")
        try:
            parse_pql_to_conditions(new_pql)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid PQL: {exc}")

    rules_path = get_rules_path()
    if not rules_path.exists():
        raise HTTPException(status_code=500, detail=f"Rules file not found: {rules_path}")

    backup_path = rules_path.with_suffix(
        f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    shutil.copy2(rules_path, backup_path)
    logger.info(f"Update: backed up rules to {backup_path}")

    try:
        from ruamel.yaml import YAML
        from ruamel.yaml.scalarstring import LiteralScalarString

        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.width = 4096

        with open(rules_path, "r", encoding="utf-8") as fh:
            doc = yaml.load(fh)

        rules_list = doc.get("rules") or doc.get("filter_rules") or []
        target = None
        for r in rules_list:
            if int(r.get("id", -1)) == rule_id:
                target = r
                break

        if target is None:
            raise HTTPException(
                status_code=404,
                detail=f"Rule ID {rule_id} not found in YAML file",
            )

        if data.name is not None:
            target["name"] = data.name
        if data.description is not None:
            target["description"] = data.description
        if data.enabled is not None:
            target["enabled"] = bool(data.enabled)
        if data.alert_on_modified is not None:
            target["alert_on_modified"] = bool(data.alert_on_modified)
        if new_pql is not None:
            target["pql"] = LiteralScalarString(new_pql) if "\n" in new_pql else new_pql

        with open(rules_path, "w", encoding="utf-8") as fh:
            yaml.dump(doc, fh)

        logger.info(f"Update: rule {rule_id} written to {rules_path}")

    except HTTPException:
        shutil.copy2(backup_path, rules_path)
        raise
    except Exception as exc:
        logger.error(f"Update: write failed, restoring backup: {exc}")
        shutil.copy2(backup_path, rules_path)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update YAML file: {exc}. Backup restored.",
        )

    try:
        reloaded = reload_rules()
        reloaded_rule = next((r for r in reloaded if r["id"] == rule_id), None)
        if reloaded_rule is not None and new_pql and not reloaded_rule.get("enabled") and data.enabled is not False:
            logger.error("Update: reloaded rule is disabled (PQL error), reverting")
            shutil.copy2(backup_path, rules_path)
            reload_rules()
            raise HTTPException(
                status_code=500,
                detail="Rule was disabled after reload (PQL error). Reverted to backup.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Update: reload failed, restoring backup: {exc}")
        shutil.copy2(backup_path, rules_path)
        reload_rules()
        raise HTTPException(
            status_code=500,
            detail=f"Reload failed after update: {exc}. Backup restored.",
        )

    refreshed = get_rule_by_id(rule_id) or {}
    return {
        "status": "ok",
        "rule_id": rule_id,
        "rule": {
            "id": refreshed.get("id", rule_id),
            "name": refreshed.get("name"),
            "enabled": refreshed.get("enabled"),
            "alert_on_modified": refreshed.get("alert_on_modified"),
            "description": refreshed.get("description"),
            "pql": refreshed.get("pql", ""),
        },
        "backup_path": str(backup_path),
    }


@router.delete("/{rule_id}")
async def delete_rule(rule_id: int):
    """Delete a rule from abusecve_filters.yaml.

    Creates a timestamped backup, removes the entry, and hot-reloads.
    RBAC is enforced centrally in the middleware via the
    ``soc_rule_delete`` toggle.
    """
    rule = get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule ID {rule_id} not found")

    rules_path = get_rules_path()
    if not rules_path.exists():
        raise HTTPException(status_code=500, detail=f"Rules file not found: {rules_path}")

    backup_path = rules_path.with_suffix(
        f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    shutil.copy2(rules_path, backup_path)
    logger.info(f"Delete: backed up rules to {backup_path}")

    try:
        from ruamel.yaml import YAML

        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.width = 4096

        with open(rules_path, "r", encoding="utf-8") as fh:
            doc = yaml.load(fh)

        key = "rules" if "rules" in doc else ("filter_rules" if "filter_rules" in doc else None)
        if key is None:
            raise HTTPException(status_code=500, detail="Rules list not found in YAML")

        rules_list = doc[key]
        before_count = len(rules_list)
        doc[key] = [r for r in rules_list if int(r.get("id", -1)) != rule_id]
        after_count = len(doc[key])

        if before_count == after_count:
            raise HTTPException(
                status_code=404,
                detail=f"Rule ID {rule_id} not found in YAML file",
            )

        with open(rules_path, "w", encoding="utf-8") as fh:
            yaml.dump(doc, fh)

        logger.info(f"Delete: removed rule {rule_id} from {rules_path}")

    except HTTPException:
        shutil.copy2(backup_path, rules_path)
        raise
    except Exception as exc:
        logger.error(f"Delete: write failed, restoring backup: {exc}")
        shutil.copy2(backup_path, rules_path)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update YAML file: {exc}. Backup restored.",
        )

    try:
        reload_rules()
    except Exception as exc:
        shutil.copy2(backup_path, rules_path)
        reload_rules()
        raise HTTPException(status_code=500, detail=f"Reload failed: {exc}. Backup restored.")

    return {
        "status": "ok",
        "rule_id": rule_id,
        "name": rule.get("name"),
        "backup_path": str(backup_path),
    }
