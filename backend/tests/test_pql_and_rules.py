"""Tests for the enhanced PQL parser, rule loader, and filter engine.

Run with: python -m pytest tests/test_pql_and_rules.py -v
"""

import sys
import os

# Ensure the backend app is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.engine.query_engine import parse_pql_to_conditions, evaluate_query


# ═══════════════════════════════════════════════════════════
# PQL Parser Tests
# ═══════════════════════════════════════════════════════════

class TestPQLTokenizer:
    """Test the tokenizer handles various edge cases."""

    def test_simple_field_value(self):
        result = parse_pql_to_conditions("vendor:fortinet")
        assert result == {"field": "vendor", "operator": "contains", "value": "fortinet"}

    def test_field_aliases(self):
        result = parse_pql_to_conditions("cvss:>=7.0")
        assert result == {"field": "cvss_score", "operator": "gte", "value": 7.0}

        result = parse_pql_to_conditions("sev:CRITICAL")
        assert result == {"field": "severity", "operator": "contains", "value": "CRITICAL"}

    def test_blank_operator(self):
        result = parse_pql_to_conditions("cvss:blank")
        assert result == {"field": "cvss_score", "operator": "blank"}

    def test_not_blank_operator(self):
        result = parse_pql_to_conditions("cvss:not_blank")
        assert result == {"field": "cvss_score", "operator": "not_blank"}

    def test_regex_with_quoted_parens(self):
        result = parse_pql_to_conditions('vendor:~"(?i)forti(net)?"')
        assert result == {"field": "vendor", "operator": "regex", "value": "(?i)forti(net)?"}

    def test_not_contains(self):
        result = parse_pql_to_conditions('description:!"edr plugin"')
        assert result == {"field": "description", "operator": "not_contains", "value": "edr plugin"}

    def test_exact_match(self):
        result = parse_pql_to_conditions("severity:=CRITICAL")
        assert result == {"field": "severity", "operator": "equal", "value": "CRITICAL"}

    def test_comma_or(self):
        result = parse_pql_to_conditions("severity:HIGH,CRITICAL")
        assert result["logic"] == "OR"
        assert len(result["conditions"]) == 2
        assert result["conditions"][0]["value"] == "HIGH"
        assert result["conditions"][1]["value"] == "CRITICAL"

    def test_kev_boolean(self):
        result = parse_pql_to_conditions("kev:true")
        assert result == {"field": "kev_flag", "operator": "equal", "value": True}

    def test_empty_string(self):
        assert parse_pql_to_conditions("") == {}
        assert parse_pql_to_conditions("   ") == {}


class TestPQLBooleanLogic:
    """Test AND/OR/NOT with proper precedence."""

    def test_explicit_and(self):
        result = parse_pql_to_conditions("vendor:forti AND cvss:>=7")
        assert result["logic"] == "AND"
        assert len(result["conditions"]) == 2

    def test_implicit_and(self):
        result = parse_pql_to_conditions("vendor:forti cvss:>=7")
        assert result["logic"] == "AND"
        assert len(result["conditions"]) == 2

    def test_or(self):
        result = parse_pql_to_conditions("vendor:forti OR vendor:microsoft")
        assert result["logic"] == "OR"
        assert len(result["conditions"]) == 2

    def test_not(self):
        result = parse_pql_to_conditions("NOT severity:LOW")
        assert result["logic"] == "NOT"
        assert result["conditions"][0]["field"] == "severity"

    def test_and_binds_tighter_than_or(self):
        # A OR B AND C  should parse as  A OR (B AND C)
        result = parse_pql_to_conditions("vendor:a OR vendor:b AND cvss:>=7")
        assert result["logic"] == "OR"
        assert len(result["conditions"]) == 2
        # Second should be the AND group
        assert result["conditions"][1]["logic"] == "AND"


class TestPQLGrouping:
    """Test parenthetical grouping."""

    def test_simple_group(self):
        result = parse_pql_to_conditions("(vendor:forti OR vendor:wazuh) AND cvss:>=7")
        assert result["logic"] == "AND"
        assert result["conditions"][0]["logic"] == "OR"
        assert result["conditions"][1]["field"] == "cvss_score"

    def test_nested_groups(self):
        result = parse_pql_to_conditions(
            "(vendor:forti OR vendor:wazuh) AND (cvss:>=7.0 OR cvss:blank)"
        )
        assert result["logic"] == "AND"
        assert result["conditions"][0]["logic"] == "OR"
        assert result["conditions"][1]["logic"] == "OR"

    def test_regex_with_parens_in_group(self):
        """Regex patterns with parens inside quotes should not break grouping."""
        result = parse_pql_to_conditions(
            '(vendor:~"(?i)forti(net)?" OR description:~"(?i)fortinet") AND cvss:>=3.0'
        )
        assert result["logic"] == "AND"
        or_group = result["conditions"][0]
        assert or_group["logic"] == "OR"
        assert or_group["conditions"][0]["operator"] == "regex"
        assert or_group["conditions"][0]["value"] == "(?i)forti(net)?"

    def test_complex_rule(self):
        """Test a real-world Fortinet-style rule."""
        pql = (
            '(vendor:~"(?i)forti(net)?" OR description:~"(?i)fortinet") '
            'AND (cvss:>=3.0 OR cvss:blank) '
            'AND (description:~"(?i)forti[-_]?edr" OR product:~"(?i)forti[-_]?mail")'
        )
        result = parse_pql_to_conditions(pql)
        assert result["logic"] == "AND"
        assert len(result["conditions"]) == 3
        # First group: vendor OR
        assert result["conditions"][0]["logic"] == "OR"
        # Second group: cvss OR blank
        assert result["conditions"][1]["logic"] == "OR"
        # Third group: product OR
        assert result["conditions"][2]["logic"] == "OR"


# ═══════════════════════════════════════════════════════════
# Evaluate Query Tests (PQL → evaluate)
# ═══════════════════════════════════════════════════════════

SAMPLE_CVE = {
    "cve_id": "CVE-2024-12345",
    "vendor": "fortinet",
    "product": "fortigate",
    "description": "A buffer overflow in FortiEDR allows remote code execution.",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "source": "NVD",
    "sources": ["NVD", "CISA_KEV"],
    "published_date": "2024-01-15",
    "modified_date": "2024-01-20",
    "kev_flag": True,
    "cpe_names": ["cpe:2.3:a:fortinet:fortiedr:5.0:*:*:*:*:*:*:*"],
    "references": [],
    "weaknesses": ["CWE-120"],
    "affected_products": ["Fortinet FortiEDR 5.0"],
}

SAMPLE_CVE_LOW = {
    "cve_id": "CVE-2024-99999",
    "vendor": "example",
    "product": "widget",
    "description": "Minor information disclosure.",
    "severity": "LOW",
    "cvss_score": 2.1,
    "cvss_vector": "",
    "source": "NVD",
    "sources": ["NVD"],
    "published_date": "2024-06-01",
    "modified_date": "2024-06-01",
    "kev_flag": False,
    "cpe_names": [],
    "references": [],
    "weaknesses": [],
    "affected_products": [],
}

SAMPLE_CVE_NO_SCORE = {
    "cve_id": "CVE-2024-00001",
    "vendor": "fortinet",
    "product": "fortiedr",
    "description": "Unrated FortiEDR vulnerability.",
    "severity": "",
    "cvss_score": None,
    "cvss_vector": "",
    "source": "MITRE",
    "sources": ["MITRE"],
    "published_date": "2024-03-01",
    "modified_date": "2024-03-01",
    "kev_flag": False,
    "cpe_names": ["cpe:2.3:a:fortinet:fortiedr:*:*:*:*:*:*:*:*"],
    "references": [],
    "weaknesses": [],
    "affected_products": ["Fortinet FortiEDR"],
}


class TestEvaluateWithPQL:
    """End-to-end: parse PQL then evaluate against sample CVEs."""

    def test_simple_vendor_match(self):
        conds = parse_pql_to_conditions("vendor:fortinet")
        assert evaluate_query(SAMPLE_CVE, conds) is True
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False

    def test_cvss_threshold(self):
        conds = parse_pql_to_conditions("cvss:>=7.0")
        assert evaluate_query(SAMPLE_CVE, conds) is True
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False

    def test_cvss_blank(self):
        conds = parse_pql_to_conditions("cvss:blank")
        assert evaluate_query(SAMPLE_CVE_NO_SCORE, conds) is True
        assert evaluate_query(SAMPLE_CVE, conds) is False

    def test_cvss_or_blank(self):
        conds = parse_pql_to_conditions("(cvss:>=3.0 OR cvss:blank)")
        assert evaluate_query(SAMPLE_CVE, conds) is True         # score 9.8
        assert evaluate_query(SAMPLE_CVE_NO_SCORE, conds) is True  # no score
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False      # score 2.1

    def test_kev_flag(self):
        conds = parse_pql_to_conditions("kev:true")
        assert evaluate_query(SAMPLE_CVE, conds) is True
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False

    def test_regex_match(self):
        conds = parse_pql_to_conditions('description:~"(?i)forti[-_]?edr"')
        assert evaluate_query(SAMPLE_CVE, conds) is True
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False

    def test_not_contains(self):
        conds = parse_pql_to_conditions("description:!deprecated")
        assert evaluate_query(SAMPLE_CVE, conds) is True

    def test_compound_fortinet_rule(self):
        """Test a full Fortinet-style rule PQL."""
        pql = (
            '(vendor:~"(?i)forti(net)?" OR description:~"(?i)fortinet" '
            'OR cpe_names:~"(?i):fortinet:") '
            'AND (cvss:>=3.0 OR cvss:blank) '
            'AND (description:~"(?i)forti[-_]?edr" OR product:~"(?i)forti[-_]?edr")'
        )
        conds = parse_pql_to_conditions(pql)
        assert evaluate_query(SAMPLE_CVE, conds) is True
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False
        assert evaluate_query(SAMPLE_CVE_NO_SCORE, conds) is True  # blank cvss, fortiedr product

    def test_not_operator(self):
        conds = parse_pql_to_conditions("vendor:fortinet AND NOT severity:LOW")
        assert evaluate_query(SAMPLE_CVE, conds) is True   # CRITICAL != LOW
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False  # wrong vendor anyway

    def test_comma_severity(self):
        conds = parse_pql_to_conditions("severity:HIGH,CRITICAL")
        assert evaluate_query(SAMPLE_CVE, conds) is True
        assert evaluate_query(SAMPLE_CVE_LOW, conds) is False


# ═══════════════════════════════════════════════════════════
# Rule Loader Tests
# ═══════════════════════════════════════════════════════════

class TestRuleLoader:
    """Test loading rules from YAML file."""

    def test_load_rules_from_file(self, tmp_path):
        import yaml
        rules_file = tmp_path / "test_rules.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [
                {
                    "id": 9001,
                    "name": "Test Rule",
                    "enabled": True,
                    "alert_on_modified": False,
                    "description": "A test rule",
                    "pql": "vendor:fortinet AND cvss:>=7.0",
                },
                {
                    "id": 9002,
                    "name": "Disabled Rule",
                    "enabled": False,
                    "pql": "vendor:disabled",
                },
            ]
        }))

        from app.engine.rule_loader import load_rules
        rules = load_rules(rules_file)

        assert len(rules) == 2
        assert rules[0]["id"] == 9001
        assert rules[0]["name"] == "Test Rule"
        assert rules[0]["_parsed_conditions"] is not None
        assert rules[1]["enabled"] is False

    def test_load_rules_pql_pre_parsed(self, tmp_path):
        import yaml
        rules_file = tmp_path / "test_rules.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [
                {
                    "id": 9001,
                    "name": "PQL Rule",
                    "enabled": True,
                    "pql": "(vendor:forti OR vendor:wazuh) AND cvss:>=3.0",
                }
            ]
        }))

        from app.engine.rule_loader import load_rules
        rules = load_rules(rules_file)

        parsed = rules[0]["_parsed_conditions"]
        assert parsed is not None
        assert parsed["logic"] == "AND"

    def test_get_rule_by_id(self, tmp_path):
        import yaml
        rules_file = tmp_path / "test_rules.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [
                {"id": 1001, "name": "Rule A", "pql": "vendor:a"},
                {"id": 1002, "name": "Rule B", "pql": "vendor:b"},
            ]
        }))

        from app.engine import rule_loader
        rule_loader._rules_loaded = False
        rule_loader.load_rules(rules_file)

        rule = rule_loader.get_rule_by_id(1001)
        assert rule is not None
        assert rule["name"] == "Rule A"

        assert rule_loader.get_rule_by_id(9999) is None

    def test_duplicate_id_skipped(self, tmp_path):
        import yaml
        rules_file = tmp_path / "test_rules.yaml"
        rules_file.write_text(yaml.dump({
            "rules": [
                {"id": 1001, "name": "First", "pql": "vendor:a"},
                {"id": 1001, "name": "Duplicate", "pql": "vendor:b"},
            ]
        }))

        from app.engine.rule_loader import load_rules
        rules = load_rules(rules_file)
        assert len(rules) == 1
        assert rules[0]["name"] == "First"


# ═══════════════════════════════════════════════════════════
# Filter Engine Tests
# ═══════════════════════════════════════════════════════════

class TestFilterEngine:
    """Test match_cve_against_rule with file-based rule dicts."""

    def _make_cve(self, **overrides):
        from dataclasses import fields as dc_fields
        from app.engine.sources.base import NormalizedCVE
        defaults = {
            "cve_id": "CVE-2024-12345",
            "vendor": "fortinet",
            "product": "fortiedr",
            "description": "FortiEDR buffer overflow",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cvss_vector": "",
            "source": "NVD",
            "sources": ["NVD"],
            "published_date": None,
            "modified_date": None,
            "kev_flag": False,
            "cpe_names": [],
            "references": [],
            "weaknesses": [],
            "affected_products": [],
        }
        defaults.update(overrides)
        return NormalizedCVE(**defaults)

    def test_pql_rule_matches(self):
        from app.engine.filter_engine import match_cve_against_rule
        from app.engine.query_engine import parse_pql_to_conditions

        rule = {
            "id": 1001,
            "name": "Test",
            "enabled": True,
            "pql": "vendor:fortinet AND cvss:>=7.0",
            "_parsed_conditions": parse_pql_to_conditions("vendor:fortinet AND cvss:>=7.0"),
        }
        cve = self._make_cve()
        assert match_cve_against_rule(cve, rule) is True

    def test_pql_rule_no_match(self):
        from app.engine.filter_engine import match_cve_against_rule
        from app.engine.query_engine import parse_pql_to_conditions

        rule = {
            "id": 1001,
            "name": "Test",
            "enabled": True,
            "pql": "vendor:microsoft AND cvss:>=7.0",
            "_parsed_conditions": parse_pql_to_conditions("vendor:microsoft AND cvss:>=7.0"),
        }
        cve = self._make_cve()
        assert match_cve_against_rule(cve, rule) is False

    def test_no_query_matches_nothing(self):
        from app.engine.filter_engine import match_cve_against_rule

        rule = {"id": 1, "name": "Empty", "enabled": True}
        cve = self._make_cve()
        assert match_cve_against_rule(cve, rule) is False

    def test_filter_cves_returns_matches(self):
        from app.engine.filter_engine import filter_cves
        from app.engine.query_engine import parse_pql_to_conditions

        rules = [
            {
                "id": 1001,
                "name": "Forti Rule",
                "enabled": True,
                "_parsed_conditions": parse_pql_to_conditions("vendor:fortinet"),
            },
        ]
        cves = [
            self._make_cve(cve_id="CVE-2024-001", vendor="fortinet"),
            self._make_cve(cve_id="CVE-2024-002", vendor="microsoft"),
        ]
        matches = filter_cves(cves, rules)
        assert len(matches) == 1
        assert matches[0].cve.cve_id == "CVE-2024-001"
        assert matches[0].rule_id == 1001


# ═══════════════════════════════════════════════════════════
# Integration: load real abusecve_filters.yaml
# ═══════════════════════════════════════════════════════════

class TestRealRulesFile:
    """Test loading the actual production rules file."""

    def test_load_production_rules(self):
        from pathlib import Path
        rules_path = Path(__file__).parent.parent.parent / "abusecve_filters.yaml"
        if not rules_path.exists():
            import pytest
            pytest.skip("Production rules file not found")

        from app.engine.rule_loader import load_rules
        rules = load_rules(rules_path)

        assert len(rules) >= 3, f"Expected at least 3 rules, got {len(rules)}"

        # All rules should have pre-parsed conditions
        for r in rules:
            assert r["_parsed_conditions"] is not None, f"Rule {r['id']} has no parsed conditions"
            assert r["id"] is not None
            assert r["name"]

    def test_production_rules_against_sample_cve(self):
        from pathlib import Path
        rules_path = Path(__file__).parent.parent.parent / "abusecve_filters.yaml"
        if not rules_path.exists():
            import pytest
            pytest.skip("Production rules file not found")

        from app.engine.rule_loader import load_rules

        rules = load_rules(rules_path)

        # Test Fortinet rule against a Fortinet CVE
        assert evaluate_query(SAMPLE_CVE, rules[0]["_parsed_conditions"]) is True
        # Test Wazuh rule against Fortinet CVE (should NOT match)
        assert evaluate_query(SAMPLE_CVE, rules[1]["_parsed_conditions"]) is False
        # Test Microsoft rule against Fortinet CVE (should NOT match)
        assert evaluate_query(SAMPLE_CVE, rules[2]["_parsed_conditions"]) is False


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
