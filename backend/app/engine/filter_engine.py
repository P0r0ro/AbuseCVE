"""Filter Engine – matches CVEs against file-based filter rules.

Rules are loaded from the YAML config file by rule_loader.py.
Each rule carries a pre-parsed conditions tree (from PQL or legacy conditions).
The engine evaluates every CVE against every enabled rule using the query engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List

from app.engine.sources.base import NormalizedCVE
from app.engine.query_engine import evaluate_query, parse_pql_to_conditions

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

    Evaluation order:
    1. Pre-parsed conditions (set by rule_loader from PQL or conditions block)
    2. Raw PQL string (fallback — parsed on demand)
    3. Raw conditions dict (fallback — evaluated directly)
    If none of these exist the rule matches nothing.
    """
    cve_dict = _cve_to_dict(cve)

    # 1. Pre-parsed conditions (fast path — already compiled at load time)
    parsed = rule.get("_parsed_conditions")
    if parsed:
        try:
            return evaluate_query(cve_dict, parsed)
        except Exception as exc:
            logger.warning(f"Rule {rule.get('id')}: condition evaluation error: {exc}")
            return False

    # 2. Raw PQL string (on-demand parse)
    pql = rule.get("pql") or rule.get("pql_query") or ""
    if pql.strip():
        try:
            conditions = parse_pql_to_conditions(pql)
            return evaluate_query(cve_dict, conditions)
        except Exception as exc:
            logger.warning(f"Rule {rule.get('id')}: PQL evaluation failed: {exc}")
            return False

    # 3. Raw conditions dict
    conditions = rule.get("conditions")
    if conditions:
        try:
            return evaluate_query(cve_dict, conditions)
        except Exception as exc:
            logger.warning(f"Rule {rule.get('id')}: conditions evaluation failed: {exc}")
            return False

    # No query defined — rule matches nothing
    return False


def filter_cves(
    cves: List[NormalizedCVE],
    rules: List[dict],
) -> List[FilterMatch]:
    """Apply all enabled filter rules to a list of CVEs.

    Returns a list of FilterMatch objects for CVEs that match at least one rule.
    """
    matches: List[FilterMatch] = []
    seen_cve_ids: set = set()

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        for cve in cves:
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
