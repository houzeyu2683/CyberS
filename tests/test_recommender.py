"""
測試 kits/recommender.py — generate_recommendation(cve_data: dict, analysis: dict) -> dict

測試範圍：
- 正常輸入：完整 cve_data + analysis，回傳完整建議 dict
- 邊界情境：Claude API 空回應、例外、analysis 欄位部分缺失
- 錯誤輸入：None、非 dict、關鍵欄位缺失
"""

import pytest
from unittest.mock import patch
from kits.recommender import generate_recommendation


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

SAMPLE_ANALYSIS = {
    "impact_summary": "Allows unauthenticated remote code execution via JNDI lookup.",
    "attack_vector": "Network",
    "attack_conditions": "No authentication required.",
    "severity_label": "Critical",
    "exploitability": "Actively exploited in the wild.",
    "affected_components": ["log4j-core 2.0-beta9 to 2.14.1"],
}

EXPECTED_KEYS = {
    "patch_actions",
    "workarounds",
    "language_specific",
    "priority",
}

VALID_PRIORITIES = {"Immediate", "Planned", "Monitor"}

MOCK_CLAUDE_RECOMMENDATION = {
    "patch_actions": ["升級 log4j-core 至 2.17.1 以上"],
    "workarounds": ["設定 log4j2.formatMsgNoLookups=true", "移除 JndiLookup class"],
    "language_specific": {
        "java": "在 pom.xml / build.gradle 中更新 log4j-core 版本",
        "python": "不直接受影響，確認無 Java 子程序呼叫",
    },
    "priority": "Immediate",
}


# ── 正常輸入 ──────────────────────────────────────────────────────────────────

class TestGenerateRecommendationNormal:
    @patch("kits.recommender.call_claude")
    def test_returns_dict_with_required_keys(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_RECOMMENDATION
        result = generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)
        assert isinstance(result, dict)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.recommender.call_claude")
    def test_priority_is_valid(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_RECOMMENDATION
        result = generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)
        assert result["priority"] in VALID_PRIORITIES

    @patch("kits.recommender.call_claude")
    def test_patch_actions_is_nonempty_list(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_RECOMMENDATION
        result = generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)
        assert isinstance(result["patch_actions"], list)
        assert len(result["patch_actions"]) > 0

    @patch("kits.recommender.call_claude")
    def test_workarounds_is_list(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_RECOMMENDATION
        result = generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)
        assert isinstance(result["workarounds"], list)

    @patch("kits.recommender.call_claude")
    def test_language_specific_is_dict(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_RECOMMENDATION
        result = generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)
        assert isinstance(result["language_specific"], dict)


# ── 邊界情境 ──────────────────────────────────────────────────────────────────

class TestGenerateRecommendationBoundary:
    @patch("kits.recommender.call_claude")
    def test_empty_workarounds_is_acceptable(self, mock_claude):
        response = {**MOCK_CLAUDE_RECOMMENDATION, "workarounds": []}
        mock_claude.return_value = response
        result = generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)
        assert result["workarounds"] == []

    @patch("kits.recommender.call_claude")
    def test_empty_language_specific_is_acceptable(self, mock_claude):
        response = {**MOCK_CLAUDE_RECOMMENDATION, "language_specific": {}}
        mock_claude.return_value = response
        result = generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)
        assert result["language_specific"] == {}

    @patch("kits.recommender.call_claude", side_effect=Exception("API error"))
    def test_raises_on_claude_api_exception(self, mock_claude):
        with pytest.raises(Exception):
            generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)

    @patch("kits.recommender.call_claude", return_value=None)
    def test_raises_or_handles_claude_returning_none(self, mock_claude):
        with pytest.raises((ValueError, TypeError, AttributeError)):
            generate_recommendation(SAMPLE_CVE_DATA, SAMPLE_ANALYSIS)

    @patch("kits.recommender.call_claude")
    def test_works_with_analysis_missing_exploitability(self, mock_claude):
        mock_claude.return_value = MOCK_CLAUDE_RECOMMENDATION
        analysis = {k: v for k, v in SAMPLE_ANALYSIS.items() if k != "exploitability"}
        result = generate_recommendation(SAMPLE_CVE_DATA, analysis)
        assert EXPECTED_KEYS.issubset(result.keys())


# ── 錯誤輸入 ──────────────────────────────────────────────────────────────────

class TestGenerateRecommendationInvalidInput:
    def test_raises_for_none_cve_data(self):
        with pytest.raises((ValueError, TypeError)):
            generate_recommendation(None, SAMPLE_ANALYSIS)

    def test_raises_for_none_analysis(self):
        with pytest.raises((ValueError, TypeError)):
            generate_recommendation(SAMPLE_CVE_DATA, None)

    def test_raises_for_both_none(self):
        with pytest.raises((ValueError, TypeError)):
            generate_recommendation(None, None)

    def test_raises_for_non_dict_cve_data(self):
        with pytest.raises((ValueError, TypeError)):
            generate_recommendation("CVE-2021-44228", SAMPLE_ANALYSIS)

    def test_raises_for_non_dict_analysis(self):
        with pytest.raises((ValueError, TypeError)):
            generate_recommendation(SAMPLE_CVE_DATA, "some string")

    def test_raises_for_missing_severity_label_in_analysis(self):
        analysis = {k: v for k, v in SAMPLE_ANALYSIS.items() if k != "severity_label"}
        with pytest.raises((ValueError, KeyError)):
            generate_recommendation(SAMPLE_CVE_DATA, analysis)
