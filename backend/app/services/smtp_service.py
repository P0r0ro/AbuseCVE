"""SMTP Service – sends alert emails and health reports via SMTP."""

from __future__ import annotations

import logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import settings

logger = logging.getLogger(__name__)

# Jinja2 template environment
template_env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html"]),
)


async def send_email(
    subject: str,
    html_body: str,
    recipients: Optional[List[str]] = None,
    text_body: Optional[str] = None,
) -> dict:
    """Send an email via SMTP.

    Returns:
        {"status": "sent"} or {"status": "failed", "error": "..."}
    """
    if not recipients:
        recipients = settings.recipient_list
    if not recipients:
        logger.warning("No recipients configured for email")
        return {"status": "failed", "error": "No recipients configured"}

    if not settings.smtp_host or not settings.smtp_user:
        logger.warning("SMTP not configured")
        return {"status": "failed", "error": "SMTP not configured"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = ", ".join(recipients)

    if text_body:
        msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            use_tls=False,
            start_tls=settings.smtp_tls,
        )
        logger.info(f"Email sent: '{subject}' to {recipients}")
        return {"status": "sent"}
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return {"status": "failed", "error": str(e)}


async def send_cve_alert(cve_data: dict, rule_name: str = "") -> dict:
    """Send a CVE alert email using the alert template."""
    try:
        template = template_env.get_template("alert_email.html")
        html = template.render(
            cve=cve_data,
            rule_name=rule_name,
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        )
    except Exception:
        # Fallback without template
        html = _fallback_alert_html(cve_data, rule_name)

    severity = cve_data.get("severity", "UNKNOWN")
    cve_id = cve_data.get("cve_id", "UNKNOWN")
    subject = f"🛡️ AbuseCVE Alert [{severity}] — {cve_id}"

    return await send_email(subject=subject, html_body=html)


async def send_health_report(report_data: dict) -> dict:
    """Send the daily health report email."""
    try:
        template = template_env.get_template("health_report.html")
        html = template.render(
            report=report_data,
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        )
    except Exception:
        html = _fallback_health_html(report_data)

    subject = f"🔒 AbuseCVE Daily Health Report — {datetime.utcnow().strftime('%Y-%m-%d')}"
    return await send_email(subject=subject, html_body=html)


async def send_test_email() -> dict:
    """Send a test email to verify SMTP configuration."""
    html = """
    <div style="font-family: 'Inter', sans-serif; background: #0F0F1A; color: #E0E0E0; padding: 40px;">
        <div style="max-width: 600px; margin: 0 auto; background: #1A1A2E; border-radius: 12px;
                    border: 1px solid rgba(124, 58, 237, 0.3); padding: 40px;">
            <h1 style="color: #A855F7; margin: 0 0 20px 0;">🛡️ AbuseCVE (≖_≖ )</h1>
            <h2 style="color: #7C3AED;">SMTP Test Successful!</h2>
            <p>Your SMTP configuration is working correctly.</p>
            <p style="color: #888; font-size: 12px;">Sent at: {}</p>
        </div>
    </div>
    """.format(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    return await send_email(
        subject="🛡️ AbuseCVE — SMTP Test",
        html_body=html,
    )


def _fallback_alert_html(cve: dict, rule_name: str) -> str:
    """Fallback alert HTML when template is not available."""
    severity = cve.get("severity", "UNKNOWN")
    severity_colors = {
        "CRITICAL": "#FF4444",
        "HIGH": "#FF8C00",
        "MEDIUM": "#FFD700",
        "LOW": "#00CED1",
    }
    color = severity_colors.get(severity, "#888")

    return f"""
    <div style="font-family: 'Inter', sans-serif; background: #0F0F1A; color: #E0E0E0; padding: 40px;">
        <div style="max-width: 600px; margin: 0 auto; background: #1A1A2E; border-radius: 12px;
                    border: 1px solid rgba(124, 58, 237, 0.3); padding: 30px;">
            <h1 style="color: #A855F7; margin: 0 0 10px 0;">🛡️ AbuseCVE Alert (≖_≖ )</h1>
            <div style="display: inline-block; background: {color}; color: #fff; padding: 4px 12px;
                        border-radius: 6px; font-weight: bold; font-size: 14px;">{severity}</div>
            <h2 style="color: #fff; margin: 20px 0 10px 0;">{cve.get("cve_id", "N/A")}</h2>
            <p><strong>Vendor:</strong> {cve.get("vendor", "N/A")}</p>
            <p><strong>Product:</strong> {cve.get("product", "N/A")}</p>
            <p><strong>CVSS:</strong> {cve.get("cvss_score", "N/A")}</p>
            <hr style="border-color: rgba(124,58,237,0.2);">
            <p>{cve.get("description", "No description available.")}</p>
            {"<p><strong>Matched Rule:</strong> " + rule_name + "</p>" if rule_name else ""}
            <p><strong>KEV:</strong> {"⚠️ Yes — Known Exploited" if cve.get("kev_flag") else "No"}</p>
            <p style="color: #888; font-size: 12px; margin-top: 20px;">
                Source: {cve.get("source", "N/A")} |
                Published: {cve.get("published_date", "N/A")}
            </p>
        </div>
    </div>
    """


def _fallback_health_html(report: dict) -> str:
    """Fallback health report HTML."""
    components = report.get("components_status", {})
    comp_rows = ""
    for name, status in components.items():
        color = "#4ADE80" if status == "ok" else "#FF4444"
        comp_rows += f'<tr><td style="padding:8px;color:#E0E0E0;">{name}</td>' \
                     f'<td style="padding:8px;color:{color};font-weight:bold;">{status}</td></tr>'

    return f"""
    <div style="font-family: 'Inter', sans-serif; background: #0F0F1A; color: #E0E0E0; padding: 40px;">
        <div style="max-width: 600px; margin: 0 auto; background: #1A1A2E; border-radius: 12px;
                    border: 1px solid rgba(124, 58, 237, 0.3); padding: 30px;">
            <h1 style="color: #A855F7; margin: 0 0 20px 0;">🔒 AbuseCVE Health Report (≖_≖ )</h1>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><th style="text-align:left;padding:8px;color:#7C3AED;border-bottom:1px solid #333;">Component</th>
                    <th style="text-align:left;padding:8px;color:#7C3AED;border-bottom:1px solid #333;">Status</th></tr>
                {comp_rows}
            </table>
            <div style="margin-top: 20px; padding: 15px; background: rgba(124,58,237,0.1); border-radius: 8px;">
                <p>🆕 New CVEs Alerted Today: <strong>{report.get("new_cves_alerted", 0)}</strong></p>
                <p>📋 Existing CVEs Seen: <strong>{report.get("existing_cves_seen", 0)}</strong></p>
                <p>🗄️ Total CVEs in DB: <strong>{report.get("total_cves_in_db", 0)}</strong></p>
                <p>🔍 Active Filters: <strong>{report.get("active_filters", 0)}</strong></p>
            </div>
        </div>
    </div>
    """
