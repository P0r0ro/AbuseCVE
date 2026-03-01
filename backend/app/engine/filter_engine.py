"""Filter Engine – matches CVEs against user-defined filter rules.

Supports:
- Legacy simple filters (vendor, products, CVSS, severity, keywords)
- Advanced query conditions using the query engine
- Multiple severity values per rule
- Alert on modified/updated CVEs
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from app.engine.sources.base import NormalizedCVE
from app.engine.query_engine import evaluate_query

logger = logging.getLogger(__name__)


@dataclass
class FilterMatch:
    """Result of a CVE matching against a filter rule."""
    cve: NormalizedCVE
    rule_id: int
    rule_name: str


def _cve_to_dict(cve: NormalizedCVE) -> dict:
    """Convert a NormalizedCVE to dict for query engine evaluation."""
    return {
        "cve_id": cve.cve_id,
        "vendor": cve.vendor or "",
        "product": cve.product or "",
        "description": cve.description or "",
        "severity": cve.severity or "",
        "cvss_score": cve.cvss_score,
        "cvss_vector": cve.cvss_vector or "",
        "source": cve.source,
        "sources": cve.sources,
        "published_date": cve.published_date.isoformat() if cve.published_date else "",
        "modified_date": cve.modified_date.isoformat() if cve.modified_date else "",
        "kev_flag": cve.kev_flag,
        "cpe_names": cve.cpe_names,
        "references": cve.references,
        "weaknesses": cve.weaknesses,
        "affected_products": cve.affected_products,
    }


def match_cve_against_rule(cve: NormalizedCVE, rule: dict) -> bool:
    """Check if a single CVE matches a filter rule.

    Supports:
    - PQL query mode (raw query string parsed to conditions)
    - Advanced query conditions using the query engine
    - Legacy simple filters (vendor, products, CVSS, severity, keywords)
    - Custom severity mapping (score ranges)
    - Include UNKNOWN (CVEs without CVSS scores)
    """
    # ── PQL query mode ───────────────────────────────────
    pql_query = rule.get("pql_query")
    if pql_query and pql_query.strip():
        cve_dict = _cve_to_dict(cve)
        try:
            from app.engine.query_engine import parse_pql_to_conditions, evaluate_query
            conditions = parse_pql_to_conditions(pql_query)
            return evaluate_query(cve_dict, conditions)
        except Exception as e:
            logger.warning(f"PQL query evaluation failed: {e}")
            return False

    # ── Advanced conditions mode ─────────────────────────
    conditions = rule.get("conditions")
    if conditions:
        cve_dict = _cve_to_dict(cve)
        return evaluate_query(cve_dict, conditions)

    # ── Legacy mode ──────────────────────────────────────

    # 1. Vendor match
    rule_vendor = (rule.get("vendor") or "").lower().strip()
    if rule_vendor:
        cve_vendor = (cve.vendor or "").lower().strip()
        cpe_vendor = (rule.get("cpe_vendor") or "").lower().strip()

        vendor_matched = False
        if rule_vendor and cve_vendor:
            if rule_vendor in cve_vendor or cve_vendor in rule_vendor:
                vendor_matched = True

        if not vendor_matched and cve.cpe_names:
            check_vendor = cpe_vendor or rule_vendor
            for cpe in cve.cpe_names:
                if check_vendor in cpe.lower():
                    vendor_matched = True
                    break

        if not vendor_matched and cve.description:
            if rule_vendor in cve.description.lower():
                vendor_matched = True

        # Check affected_products too
        if not vendor_matched and cve.affected_products:
            for ap in cve.affected_products:
                if rule_vendor in ap.lower():
                    vendor_matched = True
                    break

        if not vendor_matched:
            return False

    # 2. Product match
    products = rule.get("products") or []
    if products:
        product_matched = False
        cve_product = (cve.product or "").lower()

        for p in products:
            p_lower = p.lower().strip()
            if p_lower in cve_product or cve_product in p_lower:
                product_matched = True
                break
            if cve.cpe_names:
                for cpe in cve.cpe_names:
                    if p_lower in cpe.lower():
                        product_matched = True
                        break
            if product_matched:
                break
            if cve.description and p_lower in cve.description.lower():
                product_matched = True
                break
            # Check affected_products
            if cve.affected_products:
                for ap in cve.affected_products:
                    if p_lower in ap.lower():
                        product_matched = True
                        break
            if product_matched:
                break

        if not product_matched:
            return False

    # 3. CVSS range
    min_cvss = rule.get("min_cvss")
    max_cvss = rule.get("max_cvss")
    include_unknown = rule.get("include_unknown", False)

    if min_cvss is not None or max_cvss is not None:
        if cve.cvss_score is None:
            if not include_unknown:
                return False
            # If include_unknown, skip CVSS check for unscored CVEs
        else:
            if min_cvss is not None and cve.cvss_score < min_cvss:
                return False
            if max_cvss is not None and cve.cvss_score > max_cvss:
                return False

    # 4. Severity filter (supports multiple values + custom mapping)
    severity_mapping = rule.get("severity_mapping")
    severity_filter = rule.get("severity_filter") or []

    if severity_mapping:
        # Custom severity mapping: determine CVE severity from CVSS score
        if cve.cvss_score is not None:
            matched_severity = False
            for sev_name, score_range in severity_mapping.items():
                if isinstance(score_range, list) and len(score_range) == 2:
                    if score_range[0] <= cve.cvss_score <= score_range[1]:
                        matched_severity = True
                        break
            if not matched_severity:
                return False
        else:
            # CVE has no score — check include_unknown
            if not include_unknown:
                return False
    elif severity_filter:
        if cve.severity:
            if cve.severity.upper() not in [s.upper() for s in severity_filter]:
                return False
        else:
            # If CVE has no severity and filter requires specific ones
            if not include_unknown:
                return False

    # 5. Keyword include (products merged as default keywords)
    keywords_include = rule.get("keywords_include") or []
    if keywords_include:
        desc_lower = (cve.description or "").lower()
        cve_text = f"{desc_lower} {cve.cve_id.lower()} {(cve.vendor or '').lower()} {(cve.product or '').lower()}"
        for kw in keywords_include:
            if kw.lower() not in cve_text:
                return False

    # 6. Keyword exclude
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
