"""
測試 app.py — analyze(cve_id: str) -> dict

測試範圍：
- 正常輸入：合法 CVE ID → 回傳含必要欄位的 dict
- 錯誤輸入：非法格式 → {"error": "..."}
- 錯誤輸入：空字串 → {"error": "..."}
- 邊界情境：generate_report 拋出例外 → {"error": "..."}
"""

import pytest
from unittest.mock import patch, MagicMock
from app import analyze


# ── 共用測試資料 ──────────────────────────────────────────────────────────────

EXPECTED_REPORT_KEYS = {"cve_id", "summary", "impact", "recommendations", "risk_rating"}

MOCK_REPORT = {
    "cve_id": "CVE-2021-44228",
    "summary": "CVE-2021-44228: Apache Log4j2 JNDI remote code execution vulnerability.",
    "impact": {
        "impact_summary": "Allows unauthenticated remote code execution.",
        "attack_vector": "Network",
        "attack_conditions": "No authentication required.",
        "severity_label": "Critical",
        "exploitability": "Actively exploited in the wild.",
        "affected_components": ["log4j-core 2.0-beta9 to 2.14.1"],
    },
    "recommendations": {
        "patch_actions": ["升級 log4j-core 至 2.17.1 以上"],
        "workarounds": ["設定 log4j2.formatMsgNoLookups=true"],
        "language_specific": {"java": "更新 pom.xml 中 log4j-core 版本"},
        "priority": "Immediate",
    },
    "risk_rating": "Critical",
    "generated_at": "2026-04-03T12:00:00",
}


# ── 正常輸入 ──────────────────────────────────────────────────────────────────

class TestAnalyzeNormal:
    @patch("app.generate_report")
    def test_valid_cve_id_returns_dict(self, mock_report):
        mock_report.return_value = MOCK_REPORT
        result = analyze("CVE-2021-44228")
        assert isinstance(result, dict)

    @patch("app.generate_report")
    def test_valid_cve_id_contains_required_keys(self, mock_report):
        mock_report.return_value = MOCK_REPORT
        result = analyze("CVE-2021-44228")
        assert EXPECTED_REPORT_KEYS.issubset(result.keys())

    @patch("app.generate_report")
    def test_valid_cve_id_matches_input(self, mock_report):
        mock_report.return_value = MOCK_REPORT
        result = analyze("CVE-2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"

    @patch("app.generate_report")
    def test_valid_cve_id_has_risk_rating(self, mock_report):
        mock_report.return_value = MOCK_REPORT
        result = analyze("CVE-2021-44228")
        assert result["risk_rating"] in {"Critical", "High", "Medium", "Low"}

    @patch("app.generate_report")
    def test_generate_report_called_with_cve_id(self, mock_report):
        mock_report.return_value = MOCK_REPORT
        analyze("CVE-2021-44228")
        mock_report.assert_called_once_with("CVE-2021-44228")


# ── 錯誤輸入 ──────────────────────────────────────────────────────────────────

class TestAnalyzeInvalidInput:
    def test_invalid_format_returns_error_dict(self):
        result = analyze("abc")
        assert isinstance(result, dict)
        assert "error" in result
        assert isinstance(result["error"], str)
        assert len(result["error"]) > 0

    def test_empty_string_returns_error_dict(self):
        result = analyze("")
        assert isinstance(result, dict)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_none_input_returns_error_dict(self):
        result = analyze(None)
        assert isinstance(result, dict)
        assert "error" in result

    def test_numeric_input_returns_error_dict(self):
        result = analyze("12345")
        assert isinstance(result, dict)
        assert "error" in result

    def test_invalid_format_no_exception_propagated(self):
        """analyze 不應拋出例外，所有錯誤都應包在 {"error": ...} 中。"""
        try:
            result = analyze("not-a-cve")
            assert "error" in result
        except Exception as e:
            pytest.fail(f"analyze() raised an exception: {e}")


# ── 邊界情境 ──────────────────────────────────────────────────────────────────

class TestAnalyzeBoundary:
    @patch("app.generate_report", side_effect=Exception("fetch failed"))
    def test_generate_report_exception_returns_error_dict(self, mock_report):
        """generate_report 拋出例外時，應回傳 {"error": ...}。"""
        result = analyze("CVE-2021-44228")
        assert isinstance(result, dict)
        assert "error" in result
        assert "fetch failed" in result["error"]

    @patch("app.generate_report", side_effect=ValueError("invalid cve"))
    def test_value_error_from_report_returns_error_dict(self, mock_report):
        result = analyze("CVE-2021-44228")
        assert "error" in result

    @patch("app.generate_report", side_effect=KeyError("missing key"))
    def test_key_error_from_report_returns_error_dict(self, mock_report):
        result = analyze("CVE-2021-44228")
        assert "error" in result

    @patch("app.generate_report")
    def test_whitespace_only_input_returns_error_dict(self, mock_report):
        result = analyze("   ")
        assert "error" in result
        mock_report.assert_not_called()
