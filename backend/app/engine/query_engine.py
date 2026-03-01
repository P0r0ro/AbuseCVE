"""Advanced Query Engine – comprehensive filtering with operators, wildcards, regex.

Supports:
  Operators: equal, not_equal, contains, not_contains, blank, not_blank,
             starts_with, ends_with, not_starts_with, not_ends_with,
             regex, gte, lte, gt, lt, similarity
  Wildcards: * (any chars), ? (single char)
  Regex: PCRE2-compatible via Python re module
  Nested queries: AND/OR grouping with arbitrary depth
  Case insensitive by default
"""

from __future__ import annotations

import fnmatch
import logging
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


def _wildcard_to_regex(pattern: str) -> str:
    """Convert wildcard pattern (*, ?) to regex pattern.

    * = any number of characters
    ? = exactly one character
    """
    # Escape all regex special chars except * and ?
    result = ""
    for ch in pattern:
        if ch == "*":
            result += ".*"
        elif ch == "?":
            result += "."
        elif ch in r"\.^$+{}[]|()" :
            result += "\\" + ch
        else:
            result += ch
    return f"^{result}$"


def _has_wildcards(value: str) -> bool:
    """Check if a string contains wildcard characters."""
    return "*" in value or "?" in value


def _similarity_ratio(a: str, b: str) -> float:
    """Compute similarity ratio between two strings (0.0 to 1.0)."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def evaluate_condition(
    field_value: Any,
    operator: str,
    condition_value: Any = None,
    case_sensitive: bool = False,
) -> bool:
    """Evaluate a single condition against a field value.

    Args:
        field_value: The actual field value from the CVE/record
        operator: One of the supported operators
        condition_value: The value to compare against
        case_sensitive: Whether comparison is case-sensitive (default: False)

    Returns:
        True if the condition matches
    """
    # Handle blank/not_blank operators first (don't need condition_value)
    if operator == "blank":
        return field_value is None or str(field_value).strip() == ""

    if operator == "not_blank":
        return field_value is not None and str(field_value).strip() != ""

    # For other operators, convert to strings for comparison
    if field_value is None:
        field_str = ""
    elif isinstance(field_value, (list, dict)):
        field_str = str(field_value)
    else:
        field_str = str(field_value)

    if condition_value is None:
        cond_str = ""
    else:
        cond_str = str(condition_value)

    # Apply case insensitivity
    if not case_sensitive:
        field_str_cmp = field_str.lower()
        cond_str_cmp = cond_str.lower()
    else:
        field_str_cmp = field_str
        cond_str_cmp = cond_str

    # ── Numeric operators ────────────────────────────────
    if operator in ("gte", "lte", "gt", "lt"):
        try:
            fval = float(field_str) if field_str else 0.0
            cval = float(cond_str) if cond_str else 0.0
            if operator == "gte":
                return fval >= cval
            elif operator == "lte":
                return fval <= cval
            elif operator == "gt":
                return fval > cval
            elif operator == "lt":
                return fval < cval
        except (ValueError, TypeError):
            return False

    # ── Equal ────────────────────────────────────────────
    if operator == "equal":
        if _has_wildcards(cond_str_cmp):
            pattern = _wildcard_to_regex(cond_str_cmp)
            flags = 0 if case_sensitive else re.IGNORECASE
            return bool(re.match(pattern, field_str, flags))
        return field_str_cmp == cond_str_cmp

    # ── Not Equal ────────────────────────────────────────
    if operator == "not_equal":
        if _has_wildcards(cond_str_cmp):
            pattern = _wildcard_to_regex(cond_str_cmp)
            flags = 0 if case_sensitive else re.IGNORECASE
            return not bool(re.match(pattern, field_str, flags))
        return field_str_cmp != cond_str_cmp

    # ── Contains (no * wildcard, but ? allowed) ──────────
    if operator == "contains":
        search_val = cond_str_cmp.replace("*", "")  # Strip * from contains
        if "?" in search_val:
            # Convert ? wildcards to regex for character matching
            pattern = _wildcard_to_regex(search_val).strip("^$")
            flags = 0 if case_sensitive else re.IGNORECASE
            return bool(re.search(pattern, field_str, flags))
        return search_val in field_str_cmp

    # ── Not Contains ─────────────────────────────────────
    if operator == "not_contains":
        search_val = cond_str_cmp.replace("*", "")  # Strip * from not_contains
        if "?" in search_val:
            pattern = _wildcard_to_regex(search_val).strip("^$")
            flags = 0 if case_sensitive else re.IGNORECASE
            return not bool(re.search(pattern, field_str, flags))
        return search_val not in field_str_cmp

    # ── Starts With ──────────────────────────────────────
    if operator == "starts_with":
        if _has_wildcards(cond_str_cmp):
            pattern = _wildcard_to_regex(cond_str_cmp)
            # Modify pattern to match start only
            pattern = pattern.rstrip("$")
            flags = 0 if case_sensitive else re.IGNORECASE
            return bool(re.match(pattern, field_str, flags))
        return field_str_cmp.startswith(cond_str_cmp)

    # ── Ends With ────────────────────────────────────────
    if operator == "ends_with":
        if _has_wildcards(cond_str_cmp):
            pattern = _wildcard_to_regex(cond_str_cmp)
            pattern = pattern.lstrip("^")
            flags = 0 if case_sensitive else re.IGNORECASE
            return bool(re.search(pattern + "$", field_str, flags))
        return field_str_cmp.endswith(cond_str_cmp)

    # ── NOT Starts With ──────────────────────────────────
    if operator == "not_starts_with":
        if _has_wildcards(cond_str_cmp):
            pattern = _wildcard_to_regex(cond_str_cmp).rstrip("$")
            flags = 0 if case_sensitive else re.IGNORECASE
            return not bool(re.match(pattern, field_str, flags))
        return not field_str_cmp.startswith(cond_str_cmp)

    # ── NOT Ends With ────────────────────────────────────
    if operator == "not_ends_with":
        if _has_wildcards(cond_str_cmp):
            pattern = _wildcard_to_regex(cond_str_cmp).lstrip("^")
            flags = 0 if case_sensitive else re.IGNORECASE
            return not bool(re.search(pattern + "$", field_str, flags))
        return not field_str_cmp.endswith(cond_str_cmp)

    # ── Regex (PCRE2-compatible via Python re) ───────────
    if operator == "regex":
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            return bool(re.search(cond_str, field_str, flags))
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{cond_str}': {e}")
            return False

    # ── Similarity ───────────────────────────────────────
    if operator == "similarity":
        try:
            threshold = float(condition_value) if condition_value else 0.8
            # For similarity, compare the entire field against the value
            return _similarity_ratio(field_str, cond_str) >= threshold
        except (ValueError, TypeError):
            return _similarity_ratio(field_str, cond_str) >= 0.8

    logger.warning(f"Unknown operator: {operator}")
    return False


def _get_field_value(record: dict, field: str) -> Any:
    """Extract a field value from a CVE dict, supporting nested paths."""
    if "." in field:
        parts = field.split(".")
        current = record
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
    return record.get(field)


def evaluate_query(
    record: dict,
    query: Dict[str, Any],
) -> bool:
    """Evaluate a query (possibly nested) against a record.

    Query format:
    Simple condition:
    {
        "field": "vendor",
        "operator": "contains",
        "value": "forti",
        "case_sensitive": false
    }

    Nested query:
    {
        "logic": "AND",  // or "OR"
        "conditions": [
            {"field": "vendor", "operator": "equal", "value": "fortinet"},
            {
                "logic": "OR",
                "conditions": [
                    {"field": "severity", "operator": "equal", "value": "CRITICAL"},
                    {"field": "cvss_score", "operator": "gte", "value": 9.0}
                ]
            }
        ]
    }
    """
    # If it's a nested query with logic
    if "logic" in query:
        logic = query["logic"].upper()
        conditions = query.get("conditions", [])

        if not conditions:
            return True

        if logic == "AND":
            return all(evaluate_query(record, cond) for cond in conditions)
        elif logic == "OR":
            return any(evaluate_query(record, cond) for cond in conditions)
        elif logic == "NOT":
            # NOT applies to the first condition only
            return not evaluate_query(record, conditions[0]) if conditions else True
        else:
            logger.warning(f"Unknown logic operator: {logic}")
            return False

    # Simple condition
    field = query.get("field", "")
    operator = query.get("operator", "equal")
    value = query.get("value")
    case_sensitive = query.get("case_sensitive", False)

    field_value = _get_field_value(record, field)

    # If field value is a list, check if ANY item matches
    if isinstance(field_value, list) and operator not in ("blank", "not_blank"):
        return any(
            evaluate_condition(item, operator, value, case_sensitive)
            for item in field_value
        )

    return evaluate_condition(field_value, operator, value, case_sensitive)


def search_records(
    records: List[dict],
    query: Dict[str, Any],
) -> List[dict]:
    """Filter a list of records using a query.

    Returns records that match the query.
    """
    return [r for r in records if evaluate_query(r, query)]


# ── SQL Translation helpers ────────────────────────────────
def condition_to_sql_filter(model_class, condition: Dict[str, Any]):
    """Convert a single query condition to a SQLAlchemy filter clause.

    This translates our query language into database-level filtering
    where possible, falling back to in-memory filtering for complex operators.
    """
    from sqlalchemy import and_, or_, not_, func, cast, String

    field_name = condition.get("field", "")
    operator = condition.get("operator", "equal")
    value = condition.get("value")
    case_sensitive = condition.get("case_sensitive", False)

    # Handle nested logic
    if "logic" in condition:
        logic = condition["logic"].upper()
        sub_conditions = condition.get("conditions", [])
        sub_filters = [
            condition_to_sql_filter(model_class, c)
            for c in sub_conditions
        ]
        sub_filters = [f for f in sub_filters if f is not None]

        if not sub_filters:
            return None

        if logic == "AND":
            return and_(*sub_filters)
        elif logic == "OR":
            return or_(*sub_filters)
        elif logic == "NOT":
            return not_(sub_filters[0]) if sub_filters else None
        return None

    # Get the model column
    column = getattr(model_class, field_name, None)
    if column is None:
        logger.warning(f"Unknown field '{field_name}' for SQL filter")
        return None

    # Translate operator to SQLAlchemy
    if operator == "blank":
        return or_(column == None, column == "")

    if operator == "not_blank":
        return and_(column != None, column != "")

    if operator == "equal":
        if value and _has_wildcards(str(value)):
            # Convert wildcards to SQL LIKE pattern
            like_pattern = str(value).replace("*", "%").replace("?", "_")
            return column.ilike(like_pattern) if not case_sensitive else column.like(like_pattern)
        if case_sensitive:
            return column == value
        return func.lower(cast(column, String)) == func.lower(str(value))

    if operator == "not_equal":
        if value and _has_wildcards(str(value)):
            like_pattern = str(value).replace("*", "%").replace("?", "_")
            return ~column.ilike(like_pattern) if not case_sensitive else ~column.like(like_pattern)
        if case_sensitive:
            return column != value
        return func.lower(cast(column, String)) != func.lower(str(value))

    if operator == "contains":
        search_val = str(value or "").replace("*", "")
        if "?" in search_val:
            like_pattern = search_val.replace("?", "_")
            return column.ilike(f"%{like_pattern}%") if not case_sensitive else column.like(f"%{like_pattern}%")
        return column.ilike(f"%{search_val}%") if not case_sensitive else column.like(f"%{search_val}%")

    if operator == "not_contains":
        search_val = str(value or "").replace("*", "")
        if "?" in search_val:
            like_pattern = search_val.replace("?", "_")
            return ~column.ilike(f"%{like_pattern}%") if not case_sensitive else ~column.like(f"%{like_pattern}%")
        return ~column.ilike(f"%{search_val}%") if not case_sensitive else ~column.like(f"%{search_val}%")

    if operator == "starts_with":
        pat = str(value or "").replace("*", "%").replace("?", "_")
        return column.ilike(f"{pat}%") if not case_sensitive else column.like(f"{pat}%")

    if operator == "ends_with":
        pat = str(value or "").replace("*", "%").replace("?", "_")
        return column.ilike(f"%{pat}") if not case_sensitive else column.like(f"%{pat}")

    if operator == "not_starts_with":
        pat = str(value or "").replace("*", "%").replace("?", "_")
        return ~column.ilike(f"{pat}%") if not case_sensitive else ~column.like(f"{pat}%")

    if operator == "not_ends_with":
        pat = str(value or "").replace("*", "%").replace("?", "_")
        return ~column.ilike(f"%{pat}") if not case_sensitive else ~column.like(f"%{pat}")

    if operator == "regex":
        # PostgreSQL supports ~ (case sensitive) and ~* (case insensitive)
        if case_sensitive:
            return column.op("~")(str(value))
        return column.op("~*")(str(value))

    if operator == "gte":
        return column >= float(value)
    if operator == "lte":
        return column <= float(value)
    if operator == "gt":
        return column > float(value)
    if operator == "lt":
        return column < float(value)

    logger.warning(f"Cannot translate operator '{operator}' to SQL, skipping")
    return None


def parse_pql_to_conditions(pql_string: str) -> dict:
    """Parse a PQL (Policy Query Language) string into conditions JSON.

    Supports:
    - field:value (contains match)
    - field:"exact phrase" (exact match for multi-word values)
    - field:>N, field:<N, field:>=N, field:<=N (numeric comparisons)
    - field:=value (exact match)
    - field:~regex (regex match)
    - field:!value (not contains)
    - AND / OR / NOT boolean operators
    - Bare words search across cve_id, vendor, product, description

    Examples:
        vendor:fortinet severity:CRITICAL cvss:>7.0
        vendor:microsoft AND product:windows
        description:"buffer overflow" OR description:"remote code execution"
        kev:true severity:HIGH,CRITICAL
    """
    import re
    import shlex

    pql_string = pql_string.strip()
    if not pql_string:
        return {}

    # Try to split respecting quotes
    try:
        tokens = shlex.split(pql_string)
    except ValueError:
        tokens = pql_string.split()

    conditions_list = []
    i = 0

    while i < len(tokens):
        token = tokens[i]

        # Skip boolean operators (we'll handle them later)
        if token.upper() in ("AND", "OR", "NOT"):
            i += 1
            continue

        # Check for field:value pattern
        if ":" in token and not token.startswith(":"):
            field, _, value = token.partition(":")

            # Handle quoted values that were split
            if value.startswith('"') and not value.endswith('"'):
                # Recombine quoted value
                parts = [value]
                i += 1
                while i < len(tokens) and not tokens[i].endswith('"'):
                    parts.append(tokens[i])
                    i += 1
                if i < len(tokens):
                    parts.append(tokens[i])
                value = " ".join(parts).strip('"')
            else:
                value = value.strip('"').strip("'")

            condition = _pql_field_to_condition(field.lower(), value)
            if condition:
                conditions_list.append(condition)
        else:
            # Bare word — search across all text fields
            word = token.strip('"').strip("'")
            if word:
                conditions_list.append({
                    "logic": "OR",
                    "conditions": [
                        {"field": "cve_id", "operator": "contains", "value": word},
                        {"field": "vendor", "operator": "contains", "value": word},
                        {"field": "product", "operator": "contains", "value": word},
                        {"field": "description", "operator": "contains", "value": word},
                    ]
                })

        i += 1

    if not conditions_list:
        return {}

    # Check if original query uses OR
    if " OR " in pql_string.upper():
        return {"logic": "OR", "conditions": conditions_list}

    if len(conditions_list) == 1:
        return conditions_list[0]

    return {"logic": "AND", "conditions": conditions_list}


def _pql_field_to_condition(field: str, value: str) -> dict | None:
    """Convert a single PQL field:value pair to a condition dict."""
    # Field aliases
    field_map = {
        "id": "cve_id", "cve": "cve_id", "cveid": "cve_id",
        "desc": "description", "descr": "description",
        "sev": "severity", "level": "severity",
        "score": "cvss_score", "cvss": "cvss_score",
        "src": "source",
        "kev": "kev_flag",
        "pub": "published_date", "published": "published_date",
        "mod": "modified_date", "modified": "modified_date",
        "vec": "cvss_vector", "vector": "cvss_vector",
    }
    field = field_map.get(field, field)

    # Numeric comparisons
    if value.startswith(">="):
        return {"field": field, "operator": "gte", "value": float(value[2:])}
    if value.startswith("<="):
        return {"field": field, "operator": "lte", "value": float(value[2:])}
    if value.startswith(">"):
        return {"field": field, "operator": "gt", "value": float(value[1:])}
    if value.startswith("<"):
        return {"field": field, "operator": "lt", "value": float(value[1:])}

    # Exact match
    if value.startswith("="):
        return {"field": field, "operator": "equal", "value": value[1:]}

    # Regex match
    if value.startswith("~"):
        return {"field": field, "operator": "regex", "value": value[1:]}

    # NOT match
    if value.startswith("!"):
        return {"field": field, "operator": "not_contains", "value": value[1:]}

    # Comma-separated values (OR)
    if "," in value:
        values = [v.strip() for v in value.split(",") if v.strip()]
        return {
            "logic": "OR",
            "conditions": [
                {"field": field, "operator": "equal", "value": v}
                for v in values
            ]
        }

    # Boolean fields
    if field == "kev_flag":
        return {"field": field, "operator": "equal", "value": value.lower() in ("true", "1", "yes")}

    # Default: contains match
    return {"field": field, "operator": "contains", "value": value}
