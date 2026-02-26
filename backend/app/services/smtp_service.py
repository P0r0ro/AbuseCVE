"""SMTP Service – sends alert emails and health reports via SMTP.

Fixed: EOF errors, verbose error logging, retry with backoff.
"""

from __future__ import annotations

import logging
import traceback
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

MAX_RETRIES = 3
RETRY_DELAYS = [5, 15, 30]  # seconds


async def send_email(
    subject: str,
    html_body: str,
    recipients: Optional[List[str]] = None,
    text_body: Optional[str] = None,
) -> dict:
    """Send an email via SMTP with retry logic.

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

    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            logger.info(
                f"SMTP attempt {attempt + 1}/{MAX_RETRIES}: "
                f"host={settings.smtp_host}:{settings.smtp_port}, "
                f"tls={settings.smtp_tls}, user={settings.smtp_user}"
            )

            # Use explicit connection to avoid EOF issues
            smtp_client = aiosmtplib.SMTP(
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                use_tls=False,
                start_tls=settings.smtp_tls,
                timeout=30,
            )

            try:
                await smtp_client.connect()
                logger.debug("SMTP connected successfully")

                if settings.smtp_tls:
                    try:
                        await smtp_client.starttls()
                        logger.debug("SMTP STARTTLS completed")
                    except Exception as tls_err:
                        logger.warning(f"STARTTLS failed (may already be secure): {tls_err}")

                await smtp_client.login(settings.smtp_user, settings.smtp_password)
                logger.debug("SMTP login successful")

                await smtp_client.send_message(msg)
                logger.info(f"Email sent: '{subject}' to {recipients}")
                return {"status": "sent"}

            finally:
                try:
                    await smtp_client.quit()
                except Exception:
                    # Ignore errors on quit — connection may already be closed
                    pass

        except aiosmtplib.SMTPConnectError as e:
            last_error = f"SMTP connection failed: {e}"
            logger.error(
                f"SMTP connection error (attempt {attempt + 1}): {e}\n"
                f"Host: {settings.smtp_host}:{settings.smtp_port}\n"
                f"TLS: {settings.smtp_tls}"
            )
        except aiosmtplib.SMTPAuthenticationError as e:
            last_error = f"SMTP authentication failed: {e}"
            logger.error(f"SMTP auth error: {e}")
            return {"status": "failed", "error": last_error}  # Don't retry auth failures
        except aiosmtplib.SMTPResponseException as e:
            last_error = f"SMTP response error ({e.code}): {e.message}"
            logger.error(f"SMTP response error (attempt {attempt + 1}): code={e.code} msg={e.message}")
        except ConnectionResetError as e:
            last_error = f"Connection reset by server: {e}"
            logger.error(f"SMTP connection reset (attempt {attempt + 1}): {e}")
        except EOFError as e:
            last_error = f"Unexpected EOF from SMTP server: {e}"
            logger.error(
                f"SMTP EOF error (attempt {attempt + 1}): {e}\n"
                f"This usually means the server dropped the connection.\n"
                f"Check: 1) Port number ({settings.smtp_port}), "
                f"2) TLS setting ({settings.smtp_tls}), "
                f"3) Server supports STARTTLS on this port"
            )
        except Exception as e:
            last_error = f"Unexpected SMTP error: {type(e).__name__}: {e}"
            logger.error(
                f"SMTP unexpected error (attempt {attempt + 1}):\n"
                f"  Type: {type(e).__name__}\n"
                f"  Message: {e}\n"
                f"  Traceback: {traceback.format_exc()}"
            )

        # Wait before retry with exponential backoff
        if attempt < MAX_RETRIES - 1:
            import asyncio
            delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
            logger.info(f"SMTP retry in {delay}s...")
            await asyncio.sleep(delay)

    logger.error(f"SMTP failed after {MAX_RETRIES} attempts. Last error: {last_error}")
    return {"status": "failed", "error": last_error}


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

    sources = ", ".join(cve.get("sources", [cve.get("source", "N/A")]))
    cvss_scores_html = ""
    if cve.get("cvss_scores"):
        for provider, score_data in cve["cvss_scores"].items():
            if isinstance(score_data, dict):
                cvss_scores_html += (
                    f'<div style="margin: 4px 0; padding: 6px 12px; '
                    f'background: rgba(124,58,237,0.1); border-radius: 6px; font-size: 13px;">'
                    f'<strong>{provider}:</strong> {score_data.get("score", "N/A")} '
                    f'({score_data.get("version", "?")})</div>'
                )

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
            <p><strong>Sources:</strong> {sources}</p>
            {f'<div style="margin: 10px 0;"><strong>CVSS by Provider:</strong>{cvss_scores_html}</div>' if cvss_scores_html else ''}
            <hr style="border-color: rgba(124,58,237,0.2);">
            <p>{cve.get("description", "No description available.")}</p>
            {"<p><strong>Matched Rule:</strong> " + rule_name + "</p>" if rule_name else ""}
            <p><strong>KEV:</strong> {"⚠️ Yes — Known Exploited" if cve.get("kev_flag") else "No"}</p>
            <p style="color: #888; font-size: 12px; margin-top: 20px;">
                Source: {sources} |
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
