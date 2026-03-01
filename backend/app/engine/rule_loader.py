"""Rule Loader – reads filter rules from a YAML config file (Wazuh-style).

Rules live exclusively in a YAML file edited on the server.
The engine loads them into memory at startup and can hot-reload on demand.
No database involvement — the file is the single source of truth.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Module-level cache ────────────────────────────────────
_rules: List[Dict[str, Any]] = []
_rules_loaded: bool = False
_rules_file_path: Optional[Path] = None

# Default path inside Docker container (overridable via config)
DEFAULT_RULES_PATH = Path("/app/abusecve_filters.yaml")


def _resolve_path() -> Path:
    """Return the configured rules file path, falling back to defaults."""
    if _rules_file_path:
        return _rules_file_path

    # Check working directory first (dev mode)
    local = Path("abusecve_filters.yaml")
    if local.exists():
        return local

    return DEFAULT_RULES_PATH


def load_rules(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load and parse rules from the YAML file.

    Each rule dict in the returned list contains:
        id, name, enabled, alert_on_modified, description, pql,
        _parsed_conditions (pre-compiled from PQL)
    """
    global _rules, _rules_loaded

    import yaml
    from app.engine.query_engine import parse_pql_to_conditions

    rules_file = path or _resolve_path()

    if not rules_file.exists():
        logger.warning(f"Rules file not found: {rules_file}")
        _rules = []
        _rules_loaded = True
        return _rules

    logger.info(f"Loading rules from {rules_file}")

    with open(rules_file, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    # Support both top-level keys: 'rules' (new) and 'filter_rules' (legacy)
    raw_rules = data.get("rules") or data.get("filter_rules") or []

    parsed: List[Dict[str, Any]] = []
    seen_ids: set = set()

    for idx, r in enumerate(raw_rules):
        rule_id = r.get("id", 9000 + idx)

        if rule_id in seen_ids:
            logger.error(f"Duplicate rule ID {rule_id} — skipping")
            continue
        seen_ids.add(rule_id)

        pql = (r.get("pql") or r.get("pql_query") or "").strip()

        rule: Dict[str, Any] = {
            "id": rule_id,
            "name": r.get("name", f"Rule {rule_id}"),
            "enabled": r.get("enabled", True),
            "alert_on_modified": r.get("alert_on_modified", False),
            "description": (r.get("description") or "").strip(),
            "pql": pql,
            # Fallback: raw conditions dict (for migration period)
            "conditions": r.get("conditions"),
            "_parsed_conditions": None,
        }

        # Pre-parse PQL into conditions tree
        if pql:
            try:
                rule["_parsed_conditions"] = parse_pql_to_conditions(pql)
                logger.debug(f"Rule {rule_id}: PQL parsed OK")
            except Exception as exc:
                logger.error(f"Rule {rule_id} ({rule['name']}): PQL parse error: {exc}")
                rule["enabled"] = False  # disable broken rules
        elif rule["conditions"]:
            # Legacy conditions format — use directly
            rule["_parsed_conditions"] = rule["conditions"]
            logger.debug(f"Rule {rule_id}: using legacy conditions block")

        parsed.append(rule)

    _rules = parsed
    _rules_loaded = True
    enabled = sum(1 for r in parsed if r["enabled"])
    logger.info(f"Loaded {len(parsed)} rules ({enabled} enabled) from {rules_file}")
    return _rules


def get_rules() -> List[Dict[str, Any]]:
    """Return the cached rule list, loading from disk if needed."""
    if not _rules_loaded:
        load_rules()
    return _rules


def get_rule_by_id(rule_id: int) -> Optional[Dict[str, Any]]:
    """Look up a single rule by its numeric ID."""
    for r in get_rules():
        if r["id"] == rule_id:
            return r
    return None


def reload_rules(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Force a reload from disk (hot-reload)."""
    global _rules_loaded
    _rules_loaded = False
    return load_rules(path)


def set_rules_path(path: str | Path) -> None:
    """Override the default rules file path (called at app startup)."""
    global _rules_file_path
    _rules_file_path = Path(path)
