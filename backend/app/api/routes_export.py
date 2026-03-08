"""Export API routes – Excel export for CVEs and Alerts."""

from __future__ import annotations

import io
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from typing import Optional
from sqlalchemy import select, func, or_, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE
from app.models.alert_log import AlertLog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/export", tags=["Export"])

# ── Styling constants ────────────────────────────────
HEADER_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
HEADER_FILL = PatternFill(start_color="7C3AED", end_color="7C3AED", fill_type="solid")
HEADER_ALIGNMENT = Alignment(horizontal="center", vertical="center", wrap_text=True)
THIN_BORDER = Border(
    left=Side(style="thin", color="D0D0D0"),
    right=Side(style="thin", color="D0D0D0"),
    top=Side(style="thin", color="D0D0D0"),
    bottom=Side(style="thin", color="D0D0D0"),
)

SEVERITY_FILLS = {
    "CRITICAL": PatternFill(start_color="FFE0E0", end_color="FFE0E0", fill_type="solid"),
    "HIGH": PatternFill(start_color="FFF0E0", end_color="FFF0E0", fill_type="solid"),
    "MEDIUM": PatternFill(start_color="FFFFF0", end_color="FFFFF0", fill_type="solid"),
    "LOW": PatternFill(start_color="E0FFFF", end_color="E0FFFF", fill_type="solid"),
}

STATUS_FILLS = {
    "sent": PatternFill(start_color="E0FFE0", end_color="E0FFE0", fill_type="solid"),
    "failed": PatternFill(start_color="FFE0E0", end_color="FFE0E0", fill_type="solid"),
    "stored": PatternFill(start_color="F0F0F0", end_color="F0F0F0", fill_type="solid"),
}


def _style_header(ws, headers: list[str]):
    """Apply styling to header row."""
    for col_idx, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = HEADER_ALIGNMENT
        cell.border = THIN_BORDER
    ws.freeze_panes = "A2"


def _auto_width(ws, headers: list[str], min_width=12, max_width=60):
    """Auto-fit column widths based on content."""
    for col_idx, header in enumerate(headers, 1):
        col_letter = ws.cell(row=1, column=col_idx).column_letter
        max_len = len(header)
        for row in ws.iter_rows(min_row=2, min_col=col_idx, max_col=col_idx):
            for cell in row:
                if cell.value:
                    max_len = max(max_len, min(len(str(cell.value)), max_width))
        ws.column_dimensions[col_letter].width = max(min_width, max_len + 2)


def _apply_period_filter(query, period: Optional[str]):
    """Parse Wazuh-style period (Nd, Nw, Nm, Ny) or legacy names."""
    if not period:
        return query
    now = datetime.utcnow()
    cutoff = None

    # Wazuh-style: Nd, Nw, Nm, Ny
    if len(period) >= 2 and period[-1] in ("d", "w", "m", "y"):
        try:
            n = int(period[:-1])
            unit = period[-1]
            if unit == "d":
                cutoff = now - timedelta(days=n)
            elif unit == "w":
                cutoff = now - timedelta(weeks=n)
            elif unit == "m":
                cutoff = now - timedelta(days=n * 30)
            elif unit == "y":
                cutoff = now - timedelta(days=n * 365)
        except ValueError:
            pass

    # Legacy period names
    if cutoff is None:
        if period == "today":
            cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == "week":
            cutoff = now - timedelta(days=7)
        elif period == "month":
            cutoff = now - timedelta(days=30)
        elif period == "year":
            cutoff = now - timedelta(days=365)

    if cutoff:
        return query.where(AlertLog.sent_at >= cutoff)
    return query


# ── CVE Export ───────────────────────────────────────

@router.get("/cves")
async def export_cves(
    mode: str = Query("filtered", description="filtered or all"),
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    search: Optional[str] = None,
    source: Optional[str] = None,
    kev_only: bool = False,
    sort_by: str = Query("published_date"),
    sort_order: str = Query("desc"),
    pql: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Export CVEs to Excel (.xlsx)."""
    query = select(CVE)

    if mode != "all":
        # Apply filters
        if severity:
            sev_list = [s.strip().upper() for s in severity.split(",")]
            query = query.where(CVE.severity.in_(sev_list))
        if vendor:
            query = query.where(CVE.vendor.ilike(f"%{vendor}%"))
        if product:
            query = query.where(CVE.product.ilike(f"%{product}%"))
        if source:
            query = query.where(CVE.source == source)
        if kev_only:
            query = query.where(CVE.kev_flag == True)
        if search:
            pattern = f"%{search}%"
            query = query.where(
                or_(
                    CVE.cve_id.ilike(pattern),
                    CVE.vendor.ilike(pattern),
                    CVE.product.ilike(pattern),
                    CVE.description.ilike(pattern),
                )
            )
        if pql:
            try:
                from app.engine.query_engine import parse_pql_to_conditions, condition_to_sql_filter
                conditions = parse_pql_to_conditions(pql)
                if conditions:
                    sql_filter = condition_to_sql_filter(CVE, conditions)
                    if sql_filter is not None:
                        query = query.where(sql_filter)
            except Exception as e:
                logger.warning(f"PQL parse failed during export: {e}")

    # Sort
    sort_column = getattr(CVE, sort_by, CVE.published_date)
    query = query.order_by(desc(sort_column) if sort_order == "desc" else asc(sort_column))

    result = await db.execute(query)
    cves = result.scalars().all()

    # Build Excel
    wb = Workbook()
    ws = wb.active
    ws.title = "CVE Database"

    headers = [
        "CVE ID", "Vendor", "Product", "Severity", "CVSS Score",
        "Source", "KEV", "Published Date", "Description", "References",
    ]
    _style_header(ws, headers)

    for row_idx, cve in enumerate(cves, 2):
        ws.cell(row=row_idx, column=1, value=cve.cve_id).border = THIN_BORDER
        ws.cell(row=row_idx, column=2, value=cve.vendor or "N/A").border = THIN_BORDER
        ws.cell(row=row_idx, column=3, value=cve.product or "N/A").border = THIN_BORDER

        sev_cell = ws.cell(row=row_idx, column=4, value=cve.severity or "N/A")
        sev_cell.border = THIN_BORDER
        sev_cell.alignment = Alignment(horizontal="center")
        if cve.severity in SEVERITY_FILLS:
            sev_cell.fill = SEVERITY_FILLS[cve.severity]
            sev_cell.font = Font(bold=True)

        ws.cell(row=row_idx, column=5, value=cve.cvss_score).border = THIN_BORDER
        ws.cell(row=row_idx, column=6, value=cve.source or "N/A").border = THIN_BORDER
        ws.cell(row=row_idx, column=7, value="Yes" if cve.kev_flag else "No").border = THIN_BORDER

        pub_date = cve.published_date.strftime("%Y-%m-%d") if cve.published_date else "N/A"
        ws.cell(row=row_idx, column=8, value=pub_date).border = THIN_BORDER

        desc_val = (cve.description or "N/A")[:500]
        desc_cell = ws.cell(row=row_idx, column=9, value=desc_val)
        desc_cell.border = THIN_BORDER
        desc_cell.alignment = Alignment(wrap_text=True)

        refs = "\n".join((cve.references or [])[:5])
        ws.cell(row=row_idx, column=10, value=refs).border = THIN_BORDER

    _auto_width(ws, headers)
    # Description and References columns wider
    ws.column_dimensions["I"].width = 60
    ws.column_dimensions["J"].width = 40

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M")
    filename = f"AbuseCVE_CVEs_{mode}_{timestamp}.xlsx"

    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Alert Export ─────────────────────────────────────

@router.get("/alerts")
async def export_alerts(
    mode: str = Query("filtered", description="filtered or all"),
    period: Optional[str] = None,
    status: Optional[str] = None,
    is_new: Optional[bool] = None,
    pql: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Export alerts to Excel (.xlsx)."""
    query = select(AlertLog).order_by(AlertLog.sent_at.desc())

    if mode != "all":
        if status:
            query = query.where(AlertLog.status == status)
        if period:
            query = _apply_period_filter(query, period)
        if pql:
            search = f"%{pql}%"
            query = query.where(
                or_(
                    AlertLog.cve_id.ilike(search),
                    AlertLog.rule_name.ilike(search),
                )
            )
        if is_new is not None:
            query = query.where(AlertLog.is_new_cve == is_new)

    result = await db.execute(query)
    alerts = result.scalars().all()

    # Build Excel
    wb = Workbook()
    ws = wb.active
    ws.title = "Alerts"

    headers = ["CVE ID", "Status", "Type", "Rule", "Sent At", "Recipient", "Error"]
    _style_header(ws, headers)

    for row_idx, alert in enumerate(alerts, 2):
        ws.cell(row=row_idx, column=1, value=alert.cve_id).border = THIN_BORDER

        status_cell = ws.cell(row=row_idx, column=2, value=alert.status or "unknown")
        status_cell.border = THIN_BORDER
        status_cell.alignment = Alignment(horizontal="center")
        if alert.status in STATUS_FILLS:
            status_cell.fill = STATUS_FILLS[alert.status]

        type_val = "New" if alert.is_new_cve else "Duplicate" if alert.is_new_cve is False else "N/A"
        ws.cell(row=row_idx, column=3, value=type_val).border = THIN_BORDER
        ws.cell(row=row_idx, column=4, value=alert.rule_name or "N/A").border = THIN_BORDER

        sent_at = alert.sent_at.strftime("%Y-%m-%d %H:%M:%S") if alert.sent_at else "N/A"
        ws.cell(row=row_idx, column=5, value=sent_at).border = THIN_BORDER
        ws.cell(row=row_idx, column=6, value=alert.recipient or "N/A").border = THIN_BORDER
        ws.cell(row=row_idx, column=7, value=alert.error_message or "").border = THIN_BORDER

    _auto_width(ws, headers)

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M")
    filename = f"AbuseCVE_Alerts_{mode}_{timestamp}.xlsx"

    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
