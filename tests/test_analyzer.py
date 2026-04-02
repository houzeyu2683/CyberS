"""
測試 kits/analyzer.py — analyze_cve(cve_data: dict) -> dict

測試範圍：
- 正常輸入：完整 cve_data，回傳完整分析 dict
- 邊界情境：Claude API 回空回應、Claude API 例外
- 錯誤輸入：cve_data 缺少關鍵欄位、傳入 None / 非 dict
"""

import pytest
from unittest.mock import patch, MagicMock
from kits.analyzer import analyze_cve


# ── 共用測試資料 ──────────────────────────────────────────────────────────────

SAMPLE_CVE_DATA = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 JNDI remote code execution vulnerability.",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "published": "2021-12-10",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    "affected_packages": [{"name": "log4j-core", "version": "2.0-beta9 to 2.14.1"}],
}

EXPECTED_KEYS = {
    "impact_summary",
    "attack_vector",
    "attack_conditions",
    "severity_label",
    "exploitability",
    "affected_components",
}

VALID_SEVERITY_LABELS = {"Critical", "High", "Medium", "Low"}
VALID_ATTACK_VECTORS = {"Network", "Local", "Physical"}

MOCK_CLAUDE_ANALYSIS = {
    "impact_summary": "Allows unauthenticated remote code execution via JNDI lookup.",
    "attack_vector": "Network",
    "attack_conditions": "No authentication required; vulnerable log4j version in use.",
    "severity_label": "Critical",
    "exploitability": "Actively exploited in the wild.",
    "affected_components": ["log4j-core 2.0-beta9 to 2.14.1"],
}


# ── 正常輸入 ──────────────────────────────────────────────────────────────────

class TestAnalyzeCveNormal:
    @patch("kits.analyzer.call_claude")
    def test_returns_dict_with_required_keys(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert isinstance(result, dict)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.analyzer.call_claude")
    def test_severity_label_is_valid(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert result["severity_label"] in VALID_SEVERITY_LABELS

    @patch("kits.analyzer.call_claude")
    def test_attack_vector_is_valid(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert result["attack_vector"] in VALID_ATTACK_VECTORS

    @patch("kits.analyzer.call_claude")
    def test_affected_components_is_list(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert isinstance(result["affected_components"], list)

    @patch("kits.analyzer.call_claude")
    def test_impact_summary_is_nonempty_string(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert isinstance(result["impact_summary"], str)
        assert len(result["impact_summary"]) > 0


# ── 邊界情境 ──────────────────────────────────────────────────────────────────

class TestAnalyzeCveBoundary:
    @patch("kits.analyzer.call_claude")
    def test_handles_empty_references_in_cve_data(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        data = {**SAMPLE_CVE_DATA, "references": []}
        result = analyze_cve(data)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.analyzer.call_claude")
    def test_handles_empty_affected_packages(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        data = {**SAMPLE_CVE_DATA, "affected_packages": []}
        result = analyze_cve(data)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.analyzer.call_claude", side_effect=Exception("API timeout"))
    def test_raises_on_claude_api_exception(self, mock_claude):
        with pytest.raises(Exception):
            analyze_cve(SAMPLE_CVE_DATA)

    @patch("kits.analyzer.call_claude", return_value=None)
    def test_raises_or_handles_claude_returning_none(self, mock_claude):
        with pytest.raises((ValueError, TypeError, AttributeError)):
            analyze_cve(SAMPLE_CVE_DATA)

    @patch("kits.analyzer.call_claude")
    def test_handles_minimal_cve_data_with_only_required_fields(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_ANALYSIS
        minimal_data = {
            "cve_id": "CVE-2021-44228",
            "description": "Some description.",
            "cvss_score": 5.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "published": "2021-12-10",
            "references": [],
            "affected_packages": [],
        }
        result = analyze_cve(minimal_data)
        assert EXPECTED_KEYS.issubset(result.keys())


# ── 錯誤輸入 ──────────────────────────────────────────────────────────────────

class TestAnalyzeCveInvalidInput:
    def test_raises_for_none_input(self):
        with pytest.raises((ValueError, TypeError)):
            analyze_cve(None)

    def test_raises_for_non_dict_input(self):
        with pytest.raises((ValueError, TypeError)):
            analyze_cve("CVE-2021-44228")

    def test_raises_for_missing_description(self):
        data = {k: v for k, v in SAMPLE_CVE_DATA.items() if k != "description"}
        with pytest.raises((ValueError, KeyError)):
            analyze_cve(data)

    def test_raises_for_missing_cvss_score(self):
        data = {k: v for k, v in SAMPLE_CVE_DATA.items() if k != "cvss_score"}
        with pytest.raises((ValueError, KeyError)):
            analyze_cve(data)
