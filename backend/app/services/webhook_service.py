"""Webhook / CRM dispatch service – sends alert payloads to integration endpoints."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

import httpx

logger = logging.getLogger(__name__)


async def dispatch_webhook(integration, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Send a payload to an integration endpoint.

    Args:
        integration: Integration model instance
        payload: JSON-serializable dict to send

    Returns:
        Dict with status, status_code, and response_body or error
    """
    headers = dict(integration.headers or {})
    headers.setdefault("Content-Type", "application/json")
    headers.setdefault("User-Agent", "AbuseCVE/1.0")

    # Apply auth
    if integration.auth_type == "bearer" and integration.auth_token:
        headers["Authorization"] = f"Bearer {integration.auth_token}"
    elif integration.auth_type == "api_key" and integration.auth_token:
        headers["X-API-Key"] = integration.auth_token
    elif integration.auth_type == "basic" and integration.auth_token:
        import base64
        headers["Authorization"] = f"Basic {base64.b64encode(integration.auth_token.encode()).decode()}"

    # Format payload using template if provided
    body = payload
    if integration.payload_template:
        try:
            template = json.loads(integration.payload_template)
            body = _apply_template(template, payload)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Template parsing failed, using raw payload: {e}")

    # Apply CRM-specific formatting
    if integration.type == "ms_crm":
        body = _format_ms_crm_case(payload)
    elif integration.type == "jira":
        body = _format_jira_issue(payload)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            method = (integration.method or "POST").upper()
            if method == "PUT":
                response = await client.put(integration.url, json=body, headers=headers)
            else:
                response = await client.post(integration.url, json=body, headers=headers)

        response_body = ""
        try:
            response_body = response.text[:2000]  # Limit response size
        except Exception:
            pass

        if response.is_success:
            logger.info(f"Webhook dispatched to {integration.name}: {response.status_code}")
            return {
                "status": "success",
                "status_code": response.status_code,
                "response_body": response_body,
            }
        else:
            logger.error(f"Webhook failed for {integration.name}: {response.status_code}")
            return {
                "status": "failed",
                "status_code": response.status_code,
                "response_body": response_body,
                "error": f"HTTP {response.status_code}: {response_body[:500]}",
            }

    except httpx.TimeoutException:
        return {"status": "failed", "error": "Request timed out (30s)"}
    except httpx.ConnectError as e:
        return {"status": "failed", "error": f"Connection failed: {str(e)[:500]}"}
    except Exception as e:
        return {"status": "failed", "error": f"{type(e).__name__}: {str(e)[:500]}"}


def _apply_template(template: dict, payload: dict) -> dict:
    """Apply a template to a payload, replacing {{key}} placeholders."""
    import re
    result = {}
    for key, value in template.items():
        if isinstance(value, str):
            # Replace {{cve.field}} placeholders
            def replacer(match):
                path = match.group(1)
                parts = path.split(".")
                current = payload
                for part in parts:
                    if isinstance(current, dict):
                        current = current.get(part, "")
                    else:
                        return ""
                return str(current) if current is not None else ""
            result[key] = re.sub(r"\{\{(.+?)\}\}", replacer, value)
        elif isinstance(value, dict):
            result[key] = _apply_template(value, payload)
        else:
            result[key] = value
    return result


def _format_ms_crm_case(payload: dict) -> dict:
    """Format payload for Microsoft Dynamics CRM case creation."""
    cve = payload.get("cve", {})
    return {
        "title": f"[CVE Alert] {cve.get('cve_id', 'Unknown')} - {cve.get('severity', 'N/A')}",
        "description": (
            f"CVE: {cve.get('cve_id', 'N/A')}\n"
            f"Vendor: {cve.get('vendor', 'N/A')}\n"
            f"Product: {cve.get('product', 'N/A')}\n"
            f"Severity: {cve.get('severity', 'N/A')}\n"
            f"CVSS: {cve.get('cvss_score', 'N/A')}\n"
            f"Source: {cve.get('source', 'N/A')}\n"
            f"KEV: {'Yes' if cve.get('kev_flag') else 'No'}\n\n"
            f"Description:\n{cve.get('description', 'No description')}\n\n"
            f"Matched Rule: {payload.get('rule_name', 'N/A')}\n"
            f"Detected: {payload.get('timestamp', datetime.utcnow().isoformat())}"
        ),
        "prioritycode": _severity_to_priority(cve.get("severity")),
        "casetypecode": 2,  # Problem
        "caseorigincode": 3,  # Web
    }


def _format_jira_issue(payload: dict) -> dict:
    """Format payload for Jira issue creation."""
    cve = payload.get("cve", {})
    return {
        "fields": {
            "summary": f"[CVE] {cve.get('cve_id', 'Unknown')} - {cve.get('vendor', '')} {cve.get('product', '')}",
            "description": (
                f"*CVE:* {cve.get('cve_id', 'N/A')}\n"
                f"*Vendor:* {cve.get('vendor', 'N/A')}\n"
                f"*Product:* {cve.get('product', 'N/A')}\n"
                f"*Severity:* {cve.get('severity', 'N/A')}\n"
                f"*CVSS:* {cve.get('cvss_score', 'N/A')}\n"
                f"*Source:* {cve.get('source', 'N/A')}\n"
                f"*KEV:* {'Yes' if cve.get('kev_flag') else 'No'}\n\n"
                f"{cve.get('description', 'No description')}"
            ),
            "priority": {"name": _severity_to_jira_priority(cve.get("severity"))},
            "labels": ["cve", "security", cve.get("severity", "unknown").lower()],
        }
    }


def _severity_to_priority(severity: Optional[str]) -> int:
    """Convert CVE severity to CRM priority code."""
    mapping = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return mapping.get((severity or "").upper(), 2)


def _severity_to_jira_priority(severity: Optional[str]) -> str:
    """Convert CVE severity to Jira priority name."""
    mapping = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    return mapping.get((severity or "").upper(), "Medium")


def _build_payload(
    *,
    event: str,
    cve_dict: dict,
    rule_name: str = "",
    user: Optional[dict] = None,
    case: Optional[dict] = None,
) -> Dict[str, Any]:
    """Single source of truth for the outbound JSON shape.

    ``user`` and ``case`` are always present as keys so CRM templates
    can reference ``{{user.full_name}}`` / ``{{case.alert_id}}`` even
    when the trigger is system-generated (the keys hold ``None`` in
    that case). The placeholder engine in ``_apply_template`` renders
    those as empty strings, which is the right behaviour.
    """
    from app.config import settings as app_settings

    return {
        "event":     event,
        "source":    "AbuseCVE",
        "timestamp": datetime.utcnow().isoformat(),
        "cve":       cve_dict,
        "rule_name": rule_name,
        "contact_email": app_settings.webhook_email_address,
        "user": {
            "id":        (user or {}).get("id"),
            "username":  (user or {}).get("username"),
            "full_name": (user or {}).get("full_name"),
        },
        "case": case or {
            "alert_id":  None,
            "closed_at": None,
            "notes":     None,
        },
    }


async def _dispatch_payload_to_all(db_session, payload: Dict[str, Any]) -> None:
    """Send a fully-built payload to every enabled integration."""
    from app.models.integration import Integration
    from sqlalchemy import select

    result = await db_session.execute(
        select(Integration).where(Integration.enabled == True)
    )
    integrations = result.scalars().all()
    if not integrations:
        return

    for integration in integrations:
        try:
            outcome = await dispatch_webhook(integration, payload)
            integration.last_used   = datetime.utcnow()
            integration.last_status = outcome.get("status", "unknown")
            integration.last_error  = outcome.get("error")
            logger.info(f"Integration '{integration.name}' dispatch: {outcome.get('status')}")
        except Exception as e:  # noqa: BLE001
            integration.last_used   = datetime.utcnow()
            integration.last_status = "failed"
            integration.last_error  = str(e)
            logger.error(f"Integration '{integration.name}' failed: {e}")


async def dispatch_to_all_integrations(db_session, cve_dict: dict, rule_name: str = ""):
    """Automatic dispatch — system-generated CVE alert. No user context."""
    payload = _build_payload(event="cve_alert", cve_dict=cve_dict, rule_name=rule_name)
    await _dispatch_payload_to_all(db_session, payload)


async def dispatch_case_close(db_session, cve_dict: dict, *, user: dict, case: dict, rule_name: str = ""):
    """Analyst-triggered dispatch — fires when an alert is closed.

    Carries the closing user's identity (``user.full_name`` / username)
    and the case metadata (alert id, close timestamp, notes) so the
    receiving CRM can attribute the case correctly.
    """
    payload = _build_payload(
        event="case_closed",
        cve_dict=cve_dict,
        rule_name=rule_name,
        user=user,
        case=case,
    )
    await _dispatch_payload_to_all(db_session, payload)
