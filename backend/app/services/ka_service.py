"""Knowledge Article Service – creates CVE analysis reports."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.knowledge_article import KnowledgeArticle

logger = logging.getLogger(__name__)


async def create_knowledge_article(
    session: AsyncSession,
    title: str,
    cve_ids: List[str],
    content: Optional[str] = None,
    summary: Optional[str] = None,
    recommendations: Optional[str] = None,
    author: Optional[str] = None,
) -> dict:
    """Create a Knowledge Article from selected CVEs.

    If no content is provided, auto-generates from CVE data.
    """
    # Fetch CVE details
    result = await session.execute(
        select(CVE).where(CVE.cve_id.in_(cve_ids))
    )
    cves = result.scalars().all()

    if not content:
        content = _generate_article_content(cves, title)

    if not summary:
        summary = _generate_summary(cves)

    # Determine overall severity
    severities = [c.severity for c in cves if c.severity]
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_severity = max(severities, key=lambda s: severity_order.get(s, 0), default="UNKNOWN") if severities else "UNKNOWN"

    affected = list(set(
        f"{c.vendor or 'Unknown'} - {c.product or 'Unknown'}"
        for c in cves
    ))

    article = KnowledgeArticle(
        title=title,
        cve_ids=cve_ids,
        content=content,
        summary=summary,
        severity_assessment=max_severity,
        affected_products=affected,
        recommendations=recommendations or _generate_recommendations(cves),
        author=author or "AbuseCVE System",
        status="draft",
    )
    session.add(article)
    await session.flush()

    logger.info(f"Knowledge Article created: '{title}' (ID: {article.id})")
    return article.to_dict()


def _generate_article_content(cves: list, title: str) -> str:
    """Auto-generate markdown article content from CVE data."""
    lines = [f"# {title}\n"]
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n")
    lines.append(f"**CVEs Covered:** {len(cves)}\n")
    lines.append("---\n")

    for cve in cves:
        lines.append(f"## {cve.cve_id}\n")
        lines.append(f"**Severity:** {cve.severity or 'N/A'} | "
                     f"**CVSS:** {cve.cvss_score or 'N/A'} | "
                     f"**Vendor:** {cve.vendor or 'N/A'} | "
                     f"**Product:** {cve.product or 'N/A'}\n")

        if cve.kev_flag:
            lines.append("⚠️ **Known Exploited Vulnerability (CISA KEV)**\n")

        lines.append(f"\n{cve.description or 'No description available.'}\n")

        if cve.references:
            lines.append("\n**References:**\n")
            for ref in cve.references[:5]:
                lines.append(f"- [{ref}]({ref})\n")

        lines.append("---\n")

    return "\n".join(lines)


def _generate_summary(cves: list) -> str:
    """Generate a brief summary of the covered CVEs."""
    severity_counts = {}
    vendors = set()
    for cve in cves:
        severity_counts[cve.severity or "UNKNOWN"] = \
            severity_counts.get(cve.severity or "UNKNOWN", 0) + 1
        if cve.vendor:
            vendors.add(cve.vendor)

    parts = [f"Analysis covering {len(cves)} CVE(s)"]
    if vendors:
        parts.append(f"affecting {', '.join(vendors)}")
    if severity_counts:
        sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
        parts.append(f"({sev_str})")

    return ". ".join(parts) + "."


def _generate_recommendations(cves: list) -> str:
    """Generate generic recommendations based on CVE data."""
    recs = [
        "1. **Patch immediately** — Apply vendor-provided patches for all listed CVEs.",
        "2. **Monitor logs** — Check for indicators of compromise (IOCs) related to these vulnerabilities.",
        "3. **Network segmentation** — Isolate affected systems until patches are applied.",
    ]

    kev_cves = [c for c in cves if c.kev_flag]
    if kev_cves:
        recs.append(
            f"4. **CISA KEV Priority** — {len(kev_cves)} CVE(s) are in CISA's Known Exploited "
            f"Vulnerabilities catalog. These have been actively exploited in the wild and "
            f"should be prioritized for immediate remediation."
        )

    critical_cves = [c for c in cves if c.severity == "CRITICAL"]
    if critical_cves:
        recs.append(
            f"5. **Critical severity** — {len(critical_cves)} CVE(s) rated CRITICAL. "
            f"Consider emergency patching outside normal maintenance windows."
        )

    return "\n".join(recs)
