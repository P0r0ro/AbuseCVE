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

    # CVE alerts always go to alert recipients (analysts)
    return await send_email(subject=subject, html_body=html, recipients=settings.recipient_list)


async def send_health_report(report_data: dict) -> dict:
    """Send the daily health report email to health recipients."""
    try:
        template = template_env.get_template("health_report.html")
        html = template.render(
            report=report_data,
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        )
    except Exception:
        html = _fallback_health_html(report_data)

    subject = f"🔒 AbuseCVE Daily Health Report — {datetime.utcnow().strftime('%Y-%m-%d')}"
    return await send_email(
        subject=subject,
        html_body=html,
        recipients=settings.health_recipient_list,
    )


async def send_filter_test_email(
    rule_name: str,
    rule_id: int,
    pql: str,
    total_tested: int,
    match_count: int,
    elapsed: float,
    sample_cves: list = None,
) -> dict:
    """Send filter test results via email — confirms SMTP + filter pipeline work."""
    # Build sample CVEs table
    sample_rows = ""
    if sample_cves:
        for cve in sample_cves:
            cve_id = cve.get("cve_id", "?")
            vendor = cve.get("vendor", "?")
            severity = cve.get("severity", "?")
            cvss = cve.get("cvss_score", "?")
            sample_rows += (
                f'<tr><td style="padding:6px 10px;border-bottom:1px solid #333;">{cve_id}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #333;">{vendor}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #333;">{severity}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #333;">{cvss}</td></tr>'
            )

    sample_table = ""
    if sample_rows:
        sample_table = f"""
        <h3 style="color:#A855F7;margin-top:20px;">Sample Matched CVEs</h3>
        <table style="width:100%;border-collapse:collapse;color:#E0E0E0;">
            <tr><th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">CVE ID</th>
                <th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">Vendor</th>
                <th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">Severity</th>
                <th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">CVSS</th></tr>
            {sample_rows}
        </table>
        """
    else:
        sample_table = '<p style="color:#FF8C00;margin-top:15px;">No CVEs matched this filter rule.</p>'

    match_rate = round(match_count / total_tested * 100, 2) if total_tested else 0

    html = f"""
    <div style="font-family:'Inter',sans-serif;background:#0F0F1A;color:#E0E0E0;padding:40px;">
        <div style="max-width:600px;margin:0 auto;background:#1A1A2E;border-radius:12px;
                    border:1px solid rgba(124,58,237,0.3);padding:30px;">
            <h1 style="color:#A855F7;margin:0 0 10px 0;">🧪 AbuseCVE Filter Test</h1>
            <p style="color:#888;margin:0 0 20px 0;">SMTP + Filter Pipeline Verification</p>
            <div style="margin:15px 0;padding:15px;background:rgba(124,58,237,0.1);border-radius:8px;">
                <p><strong>Rule:</strong> {rule_name} (ID: {rule_id})</p>
                <p><strong>PQL:</strong> <code style="color:#A855F7;">{pql[:200]}</code></p>
            </div>
            <div style="margin:15px 0;padding:15px;background:rgba(74,222,128,0.1);border-radius:8px;">
                <p>📋 Total CVEs Tested: <strong>{total_tested:,}</strong></p>
                <p>✅ Matches Found: <strong>{match_count:,}</strong> ({match_rate}%)</p>
                <p>⏱️ Elapsed: <strong>{elapsed}s</strong></p>
            </div>
            {sample_table}
            <p style="color:#4ADE80;font-weight:bold;margin-top:20px;">
                ✅ If you received this email, SMTP and the filter pipeline are working correctly.
            </p>
            <p style="color:#888;font-size:12px;margin-top:15px;">
                Sent at: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
            </p>
        </div>
    </div>
    """

    subject = f"🧪 AbuseCVE Filter Test — {rule_name}: {match_count} matches"
    return await send_email(subject=subject, html_body=html)


async def send_scan_summary(scan_result: dict, matched_cves: list = None) -> dict:
    """Send a scan cycle summary email.

    Routing logic:
    - Scan with >0 alerts → sent to ALERT_RECIPIENTS (analysts see actionable results)
    - Scan with 0 alerts → sent to SCAN_RECIPIENTS only (admin/debug, reduces analyst noise)
    """
    total_fetched = scan_result.get("total_fetched", 0)
    filtered = scan_result.get("filtered", 0)
    new_alerted = scan_result.get("new_alerted", 0)
    alerts_failed = scan_result.get("alerts_failed", 0)
    existing = scan_result.get("existing", 0)
    total_new = scan_result.get("total_new_stored", 0)

    # Build matched CVEs table
    matched_rows = ""
    if matched_cves:
        for cve in matched_cves[:20]:
            cve_id = getattr(cve, "cve_id", None) or (cve.get("cve_id") if isinstance(cve, dict) else "?")
            vendor = getattr(cve, "vendor", None) or (cve.get("vendor") if isinstance(cve, dict) else "?")
            severity = getattr(cve, "severity", None) or (cve.get("severity") if isinstance(cve, dict) else "?")
            cvss = getattr(cve, "cvss_score", None) or (cve.get("cvss_score") if isinstance(cve, dict) else "?")
            matched_rows += (
                f'<tr><td style="padding:6px 10px;border-bottom:1px solid #333;">{cve_id}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #333;">{vendor}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #333;">{severity}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #333;">{cvss}</td></tr>'
            )

    matched_table = ""
    if matched_rows:
        matched_table = f"""
        <h3 style="color:#A855F7;margin-top:20px;">Matched CVEs (up to 20)</h3>
        <table style="width:100%;border-collapse:collapse;color:#E0E0E0;">
            <tr><th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">CVE ID</th>
                <th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">Vendor</th>
                <th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">Severity</th>
                <th style="text-align:left;padding:6px 10px;color:#7C3AED;border-bottom:1px solid #555;">CVSS</th></tr>
            {matched_rows}
        </table>
        """

    status_color = "#4ADE80" if alerts_failed == 0 else "#FF8C00"
    status_text = "All alerts sent" if new_alerted > 0 and alerts_failed == 0 else (
        "No new CVEs matched" if new_alerted == 0 and total_fetched > 0 else
        f"{alerts_failed} alert(s) failed" if alerts_failed > 0 else
        "No CVEs fetched"
    )

    html = f"""
    <div style="font-family:'Inter',sans-serif;background:#0F0F1A;color:#E0E0E0;padding:40px;">
        <div style="max-width:600px;margin:0 auto;background:#1A1A2E;border-radius:12px;
                    border:1px solid rgba(124,58,237,0.3);padding:30px;">
            <h1 style="color:#A855F7;margin:0 0 10px 0;">🔍 AbuseCVE Scan Summary</h1>
            <div style="display:inline-block;background:{status_color};color:#fff;padding:4px 12px;
                        border-radius:6px;font-weight:bold;font-size:14px;">{status_text}</div>
            <div style="margin-top:20px;padding:15px;background:rgba(124,58,237,0.1);border-radius:8px;">
                <p>📡 Total Fetched: <strong>{total_fetched}</strong></p>
                <p>🔍 Matched Filters: <strong>{filtered}</strong></p>
                <p>🆕 New CVEs Stored: <strong>{total_new}</strong></p>
                <p>📬 Alerts Sent: <strong>{new_alerted}</strong></p>
                <p>❌ Alerts Failed: <strong>{alerts_failed}</strong></p>
                <p>🔄 Existing CVEs Updated: <strong>{existing}</strong></p>
            </div>
            {matched_table}
            <p style="color:#888;font-size:12px;margin-top:20px;">
                Scan completed at: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
            </p>
        </div>
    </div>
    """

    subject = f"🔍 AbuseCVE Scan — {new_alerted} alerts, {total_fetched} fetched"

    # Route: scans with alerts go to analysts; 0-alert scans go to admin/scan recipients only
    if new_alerted > 0:
        recipients = settings.recipient_list  # Alert recipients (analysts)
    else:
        recipients = settings.scan_recipient_list  # Scan-only recipients (admin/debug)

    return await send_email(subject=subject, html_body=html, recipients=recipients)


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
        if isinstance(status, dict):
            continue  # skip nested dicts (redis_details, etc.)
        color = "#4ADE80" if (isinstance(status, str) and status.startswith("ok")) else "#FF4444"
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
                <h3 style="color:#A855F7;margin:0 0 10px 0;">Today's Alert Activity</h3>
                <p>✅ Alerts Sent Today: <strong>{report.get("new_cves_alerted", 0)}</strong></p>
                <p>❌ Alerts Failed Today: <strong>{report.get("alerts_failed_today", 0)}</strong></p>
                <p>🆕 New CVE Alerts Today: <strong>{report.get("new_cve_alerts_today", 0)}</strong></p>
                <p>📋 Existing CVEs Seen: <strong>{report.get("existing_cves_seen", 0)}</strong></p>
                <p>🗄️ Total CVEs in DB: <strong>{report.get("total_cves_in_db", 0)}</strong></p>
                <p>🔍 Active Filters: <strong>{report.get("active_filters", 0)}</strong></p>
            </div>
        </div>
    </div>
    """

