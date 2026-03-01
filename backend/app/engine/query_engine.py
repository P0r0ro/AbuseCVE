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


def _tokenize_pql(pql: str) -> List[str]:
    """Tokenize a PQL string into a flat list of tokens.

    Handles:
    - Parentheses as standalone grouping tokens
    - Quoted values (field:~"regex with parens") kept intact within tokens
    - Whitespace as delimiter (outside quotes)
    """
    tokens: List[str] = []
    i = 0
    n = len(pql)

    while i < n:
        c = pql[i]

        # Skip whitespace
        if c in " \t\n\r":
            i += 1
            continue

        # Standalone grouping parentheses
        if c == "(":
            tokens.append("(")
            i += 1
            continue
        if c == ")":
            tokens.append(")")
            i += 1
            continue

        # Accumulate a token until whitespace or unquoted paren
        j = i
        while j < n and pql[j] not in " \t\n\r()":
            if pql[j] in ('"', "'"):
                # Consume entire quoted segment (may contain parens/spaces)
                quote = pql[j]
                j += 1
                while j < n and pql[j] != quote:
                    j += 1
                if j < n:
                    j += 1  # past closing quote
            else:
                j += 1

        tokens.append(pql[i:j])
        i = j

    return tokens


def _parse_pql_expression(tokens: List[str], pos: List[int]) -> dict:
    """Parse: term (OR term)*   — OR has lowest precedence."""
    left = _parse_pql_term(tokens, pos)
    parts = [left]

    while pos[0] < len(tokens) and tokens[pos[0]].upper() == "OR":
        pos[0] += 1  # consume OR
        parts.append(_parse_pql_term(tokens, pos))

    if len(parts) == 1:
        return parts[0]
    return {"logic": "OR", "conditions": parts}


def _parse_pql_term(tokens: List[str], pos: List[int]) -> dict:
    """Parse: factor (AND factor)*   — AND binds tighter than OR.

    Implicit AND: two adjacent conditions without an explicit operator
    are joined with AND (e.g.  ``vendor:forti cvss:>=7``).
    """
    left = _parse_pql_factor(tokens, pos)
    parts = [left]

    while pos[0] < len(tokens):
        tok = tokens[pos[0]]
        upper = tok.upper()
        if upper == "AND":
            pos[0] += 1  # explicit AND
            parts.append(_parse_pql_factor(tokens, pos))
        elif upper == "OR" or tok == ")":
            break  # let the caller handle these
        else:
            # Implicit AND — next token is a condition/group, not a boolean op
            parts.append(_parse_pql_factor(tokens, pos))

    if len(parts) == 1:
        return parts[0]
    return {"logic": "AND", "conditions": parts}


def _parse_pql_factor(tokens: List[str], pos: List[int]) -> dict:
    """Parse: NOT factor | ( expression ) | condition_token."""
    if pos[0] >= len(tokens):
        return {}

    tok = tokens[pos[0]]

    # NOT prefix
    if tok.upper() == "NOT":
        pos[0] += 1
        inner = _parse_pql_factor(tokens, pos)
        return {"logic": "NOT", "conditions": [inner]}

    # Parenthesised sub-expression
    if tok == "(":
        pos[0] += 1  # consume (
        expr = _parse_pql_expression(tokens, pos)
        if pos[0] < len(tokens) and tokens[pos[0]] == ")":
            pos[0] += 1  # consume )
        return expr

    # Leaf condition token
    pos[0] += 1
    return _parse_pql_token(tok)


def _parse_pql_token(token: str) -> dict:
    """Convert a single token (field:value or bare word) into a condition dict."""
    if ":" in token and not token.startswith(":"):
        field, _, value = token.partition(":")
        # Strip outer quotes from value
        for q in ('"', "'"):
            if value.startswith(q) and value.endswith(q) and len(value) > 1:
                value = value[1:-1]
                break
        cond = _pql_field_to_condition(field.lower(), value)
        return cond or {}

    # Bare word — search across all major text fields
    word = token.strip('"').strip("'")
    if not word or word.upper() in ("AND", "OR", "NOT"):
        return {}
    return {
        "logic": "OR",
        "conditions": [
            {"field": "cve_id", "operator": "contains", "value": word},
            {"field": "vendor", "operator": "contains", "value": word},
            {"field": "product", "operator": "contains", "value": word},
            {"field": "description", "operator": "contains", "value": word},
        ],
    }


def parse_pql_to_conditions(pql_string: str) -> dict:
    """Parse a PQL (Policy Query Language) string into a conditions dict.

    Uses a recursive-descent parser with proper operator precedence:
      - OR  (lowest)
      - AND (implicit between adjacent terms, or explicit)
      - NOT (prefix, highest)
      - ( ) grouping

    Supports:
      field:value          contains match (case-insensitive)
      field:"multi word"   contains match with spaces
      field:=value         exact match
      field:~pattern       regex match  (quote if pattern has parens)
      field:!value         not-contains
      field:>=N  >N <N <=N numeric comparisons
      field:blank          field is null / empty
      field:not_blank      field has a value
      field:HIGH,CRITICAL  comma-separated OR of exact values
      kev:true             boolean shorthand
      AND OR NOT ( )       boolean logic with grouping

    Field aliases:
      id/cve/cveid → cve_id    desc → description
      sev/level → severity      cvss/score → cvss_score
      kev → kev_flag            pub → published_date  mod → modified_date

    Examples:
      vendor:fortinet AND severity:CRITICAL,HIGH AND cvss:>=7.0
      (vendor:~"(?i)forti(net)?" OR description:~"(?i)fortinet") AND cvss:>=3.0
      kev:true AND NOT severity:LOW
    """
    pql_string = pql_string.strip()
    if not pql_string:
        return {}

    tokens = _tokenize_pql(pql_string)
    if not tokens:
        return {}

    pos = [0]
    result = _parse_pql_expression(tokens, pos)
    return result or {}


# ── PQL field:value helpers ────────────────────────────────

# Reusable alias map
PQL_FIELD_ALIASES: Dict[str, str] = {
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


def _strip_quotes(v: str) -> str:
    """Remove surrounding quotes from a value string."""
    for q in ('"', "'"):
        if v.startswith(q) and v.endswith(q) and len(v) > 1:
            return v[1:-1]
    return v


def _pql_field_to_condition(field: str, value: str) -> dict | None:
    """Convert a single PQL field:value pair to a condition dict."""
    field = PQL_FIELD_ALIASES.get(field, field)

    # Special operators: blank / not_blank
    val_lower = value.lower().strip()
    if val_lower == "blank":
        return {"field": field, "operator": "blank"}
    if val_lower in ("not_blank", "notblank"):
        return {"field": field, "operator": "not_blank"}

    # Numeric comparisons (must check >= / <= before > / <)
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
        return {"field": field, "operator": "equal", "value": _strip_quotes(value[1:])}

    # Regex match
    if value.startswith("~"):
        return {"field": field, "operator": "regex", "value": _strip_quotes(value[1:])}

    # NOT match
    if value.startswith("!"):
        return {"field": field, "operator": "not_contains", "value": _strip_quotes(value[1:])}

    # Comma-separated values → OR of exact matches
    if "," in value:
        values = [v.strip() for v in value.split(",") if v.strip()]
        return {
            "logic": "OR",
            "conditions": [
                {"field": field, "operator": "equal", "value": v}
                for v in values
            ],
        }

    # Boolean fields
    if field == "kev_flag":
        return {"field": field, "operator": "equal", "value": value.lower() in ("true", "1", "yes")}

    # Default: contains match
    return {"field": field, "operator": "contains", "value": _strip_quotes(value)}
