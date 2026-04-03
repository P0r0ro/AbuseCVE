"""Feedback API — Bug reports and suggestions from analysts."""

import json
import logging
import os
from datetime import datetime
from typing import Literal
from io import BytesIO

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/feedback", tags=["Feedback"])

FEEDBACK_FILE = "/app/feedback_data.json"

COMPONENTS = ("abusecve", "abusef", "abusevt", "portal")
TYPES = ("bug", "suggestion")
SEVERITIES = ("informational", "low", "medium", "high")


class FeedbackRequest(BaseModel):
    analyst_name: str = Field(..., min_length=1, max_length=100)
    component: Literal["abusecve", "abusef", "abusevt", "portal"]
    type: Literal["bug", "suggestion"]
    severity: Literal["informational", "low", "medium", "high"]
    description: str = Field(..., min_length=1, max_length=5000)


def _load_feedback() -> list[dict]:
    if os.path.exists(FEEDBACK_FILE):
        try:
            with open(FEEDBACK_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def _save_feedback(data: list[dict]):
    with open(FEEDBACK_FILE, "w") as f:
        json.dump(data, f, indent=2)


SEVERITY_COLORS = {
    "informational": "#94a3b8",
    "low": "#eab308",
    "medium": "#f97316",
    "high": "#ef4444",
}


@router.post("")
async def submit_feedback(req: FeedbackRequest):
    """Submit a bug report or suggestion. Sends email and stores for export."""

    entry = {
        "id": f"fb-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "analyst_name": req.analyst_name,
        "component": req.component,
        "type": req.type,
        "severity": req.severity,
        "description": req.description,
        "submitted_at": datetime.utcnow().isoformat(),
    }

    # Store
    feedback_list = _load_feedback()
    feedback_list.insert(0, entry)
    _save_feedback(feedback_list)

    # Send email
    email_sent = False
    try:
        from app.services.smtp_service import send_email

        severity_upper = req.severity.upper()
        type_upper = req.type.upper()
        component_upper = req.component.upper()
        subject = f"[{severity_upper}]: [{type_upper}] on [{component_upper}] submitted by {req.analyst_name}"

        sev_color = SEVERITY_COLORS.get(req.severity, "#94a3b8")

        html_body = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #1B2631; color: #FBFCFC; padding: 24px; border-radius: 12px;">
            <h2 style="color: #F1C40F; margin-top: 0;">AbuseSuite Feedback</h2>

            <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
                <tr>
                    <td style="padding: 8px 12px; color: #5D6D7E; font-size: 13px;">Analyst</td>
                    <td style="padding: 8px 12px; color: #FBFCFC; font-weight: 600;">{req.analyst_name}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 12px; color: #5D6D7E; font-size: 13px;">Component</td>
                    <td style="padding: 8px 12px; color: #FBFCFC;">{req.component}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 12px; color: #5D6D7E; font-size: 13px;">Type</td>
                    <td style="padding: 8px 12px; color: #FBFCFC;">{req.type.capitalize()}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 12px; color: #5D6D7E; font-size: 13px;">Severity</td>
                    <td style="padding: 8px 12px;">
                        <span style="background: {sev_color}20; color: {sev_color}; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600;">
                            {req.severity.upper()}
                        </span>
                    </td>
                </tr>
            </table>

            <div style="background: rgba(255,255,255,0.05); border-radius: 8px; padding: 16px; border-left: 3px solid {sev_color};">
                <p style="margin: 0; color: #5D6D7E; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Description</p>
                <p style="margin: 0; color: #FBFCFC; line-height: 1.6; white-space: pre-wrap;">{req.description}</p>
            </div>

            <p style="color: #5D6D7E; font-size: 11px; margin-top: 16px; text-align: right;">
                Submitted: {entry['submitted_at']}
            </p>
        </div>
        """

        from app.config import settings
        result = await send_email(subject=subject, html_body=html_body, recipients=settings.feedback_recipient_list)
        email_sent = result.get("status") == "sent"
    except Exception as e:
        logger.error(f"Failed to send feedback email: {e}")

    return {
        "status": "ok",
        "message": "Feedback submitted successfully",
        "email_sent": email_sent,
        "id": entry["id"],
    }


@router.get("/export")
async def export_feedback():
    """Export all feedback as a formatted Excel file."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    except ImportError:
        return {"error": "openpyxl not installed"}

    feedback_list = _load_feedback()

    wb = Workbook()
    ws = wb.active
    ws.title = "Feedback Report"

    # Column widths
    ws.column_dimensions["A"].width = 12
    ws.column_dimensions["B"].width = 22
    ws.column_dimensions["C"].width = 18
    ws.column_dimensions["D"].width = 14
    ws.column_dimensions["E"].width = 16
    ws.column_dimensions["F"].width = 60
    ws.column_dimensions["G"].width = 22

    # Title row
    title_fill = PatternFill(start_color="1B2631", end_color="1B2631", fill_type="solid")
    title_font = Font(name="Calibri", size=16, bold=True, color="F1C40F")
    ws.merge_cells("A1:G1")
    title_cell = ws["A1"]
    title_cell.value = "AbuseSuite — Feedback Report"
    title_cell.font = title_font
    title_cell.fill = title_fill
    title_cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 40

    # Header row
    headers = ["ID", "Submitted At", "Analyst", "Type", "Severity", "Description", "Component"]
    header_fill = PatternFill(start_color="2C3E50", end_color="2C3E50", fill_type="solid")
    header_font = Font(name="Calibri", size=11, bold=True, color="FBFCFC")
    header_border = Border(bottom=Side(style="thin", color="F1C40F"))

    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=2, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = header_border
    ws.row_dimensions[2].height = 28

    # Severity color fills
    sev_fills = {
        "informational": PatternFill(start_color="94a3b8", end_color="94a3b8", fill_type="solid"),
        "low": PatternFill(start_color="eab308", end_color="eab308", fill_type="solid"),
        "medium": PatternFill(start_color="f97316", end_color="f97316", fill_type="solid"),
        "high": PatternFill(start_color="ef4444", end_color="ef4444", fill_type="solid"),
    }
    sev_fonts = {
        "informational": Font(color="1B2631", bold=True),
        "low": Font(color="1B2631", bold=True),
        "medium": Font(color="FFFFFF", bold=True),
        "high": Font(color="FFFFFF", bold=True),
    }

    type_fills = {
        "bug": PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid"),
        "suggestion": PatternFill(start_color="DBEAFE", end_color="DBEAFE", fill_type="solid"),
    }
    type_fonts = {
        "bug": Font(color="DC2626", bold=True),
        "suggestion": Font(color="2563EB", bold=True),
    }

    alt_fill = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
    wrap_alignment = Alignment(wrap_text=True, vertical="top")

    for i, entry in enumerate(feedback_list):
        row = i + 3
        ws.cell(row=row, column=1, value=entry.get("id", ""))
        ws.cell(row=row, column=2, value=entry.get("submitted_at", ""))
        ws.cell(row=row, column=3, value=entry.get("analyst_name", ""))

        type_cell = ws.cell(row=row, column=4, value=entry.get("type", "").capitalize())
        t = entry.get("type", "")
        if t in type_fills:
            type_cell.fill = type_fills[t]
            type_cell.font = type_fonts[t]
        type_cell.alignment = Alignment(horizontal="center", vertical="top")

        sev_cell = ws.cell(row=row, column=5, value=entry.get("severity", "").upper())
        sev = entry.get("severity", "")
        if sev in sev_fills:
            sev_cell.fill = sev_fills[sev]
            sev_cell.font = sev_fonts[sev]
        sev_cell.alignment = Alignment(horizontal="center", vertical="top")

        desc_cell = ws.cell(row=row, column=6, value=entry.get("description", ""))
        desc_cell.alignment = wrap_alignment

        ws.cell(row=row, column=7, value=entry.get("component", ""))

        # Alternate row shading (except severity/type columns)
        if i % 2 == 1:
            for col in (1, 2, 3, 6, 7):
                ws.cell(row=row, column=col).fill = alt_fill

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    filename = f"AbuseSuite_Feedback_{datetime.utcnow().strftime('%Y%m%d')}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
