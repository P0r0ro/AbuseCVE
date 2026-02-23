"""Filter Engine – matches CVEs against user-defined filter rules.

Supports fine-grained filtering:
- Vendor match (case-insensitive)
- Product list (e.g., only FortiGate, FortiEDR from Fortinet)
- CVSS score range (min/max)
- Severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Keyword include/exclude in descriptions
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from app.engine.sources.base import NormalizedCVE

logger = logging.getLogger(__name__)


@dataclass
class FilterMatch:
    """Result of a CVE matching against a filter rule."""
    cve: NormalizedCVE
    rule_id: int
    rule_name: str


def match_cve_against_rule(cve: NormalizedCVE, rule: dict) -> bool:
    """Check if a single CVE matches a filter rule.

    Args:
        cve: NormalizedCVE object
        rule: dict with keys: vendor, products, min_cvss, max_cvss,
              severity_filter, keywords_include, keywords_exclude, cpe_vendor

    Returns:
        True if CVE matches all specified criteria
    """
    # ── 1. Vendor match ──────────────────────────────────
    rule_vendor = (rule.get("vendor") or "").lower().strip()
    if not rule_vendor:
        return False

    cve_vendor = (cve.vendor or "").lower().strip()
    cpe_vendor = (rule.get("cpe_vendor") or "").lower().strip()

    vendor_matched = False
    # Check direct vendor name match
    if rule_vendor and cve_vendor:
        if rule_vendor in cve_vendor or cve_vendor in rule_vendor:
            vendor_matched = True

    # Check CPE names for vendor match
    if not vendor_matched and cve.cpe_names:
        check_vendor = cpe_vendor or rule_vendor
        for cpe in cve.cpe_names:
            cpe_lower = cpe.lower()
            if check_vendor in cpe_lower:
                vendor_matched = True
                break

    # Check description for vendor name
    if not vendor_matched and cve.description:
        if rule_vendor in cve.description.lower():
            vendor_matched = True

    if not vendor_matched:
        return False

    # ── 2. Product match ─────────────────────────────────
    products = rule.get("products") or []
    if products:
        product_matched = False
        cve_product = (cve.product or "").lower()

        for p in products:
            p_lower = p.lower().strip()
            # Check product field
            if p_lower in cve_product or cve_product in p_lower:
                product_matched = True
                break
            # Check CPE names
            if cve.cpe_names:
                for cpe in cve.cpe_names:
                    if p_lower in cpe.lower():
                        product_matched = True
                        break
            if product_matched:
                break
            # Check description
            if cve.description and p_lower in cve.description.lower():
                product_matched = True
                break

        if not product_matched:
            return False

    # ── 3. CVSS range ────────────────────────────────────
    min_cvss = rule.get("min_cvss")
    max_cvss = rule.get("max_cvss")
    if min_cvss is not None and cve.cvss_score is not None:
        if cve.cvss_score < min_cvss:
            return False
    if max_cvss is not None and cve.cvss_score is not None:
        if cve.cvss_score > max_cvss:
            return False

    # ── 4. Severity filter ───────────────────────────────
    severity_filter = rule.get("severity_filter") or []
    if severity_filter and cve.severity:
        if cve.severity.upper() not in [s.upper() for s in severity_filter]:
            return False

    # ── 5. Keyword include ───────────────────────────────
    keywords_include = rule.get("keywords_include") or []
    if keywords_include and cve.description:
        desc_lower = cve.description.lower()
        for kw in keywords_include:
            if kw.lower() not in desc_lower:
                return False

    # ── 6. Keyword exclude ───────────────────────────────
    keywords_exclude = rule.get("keywords_exclude") or []
    if keywords_exclude and cve.description:
        desc_lower = cve.description.lower()
        for kw in keywords_exclude:
            if kw.lower() in desc_lower:
                return False

    return True


def filter_cves(
    cves: List[NormalizedCVE],
    rules: List[dict],
) -> List[FilterMatch]:
    """Apply all enabled filter rules to a list of CVEs.

    Returns a list of FilterMatch objects for CVEs that match at least one rule.
    """
    matches: List[FilterMatch] = []
    seen_cve_ids = set()

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        for cve in cves:
            # Avoid duplicate matches
            if cve.cve_id in seen_cve_ids:
                continue

            if match_cve_against_rule(cve, rule):
                matches.append(FilterMatch(
                    cve=cve,
                    rule_id=rule.get("id", 0),
                    rule_name=rule.get("name", ""),
                ))
                seen_cve_ids.add(cve.cve_id)
                logger.debug(f"CVE {cve.cve_id} matched rule '{rule.get('name')}'")

    logger.info(f"Filter engine: {len(matches)} matches from {len(cves)} CVEs "
                f"against {len(rules)} rules")
    return matches
