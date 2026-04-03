"""
測試 kits/reporter.py — generate_report(cve_id, check_poc, check_kev) -> dict

測試範圍：
- 單元測試：mock fetcher/analyzer/recommender，驗證報告組裝邏輯
- threat_intel 參數：check_poc/check_kev 各種組合
- 整合測試：使用真實 CVE ID（CVE-2021-44228），標記為需要網路
- 邊界情境：fetch_cve 拋出例外、analyzer/recommender 回傳不完整資料
- 錯誤輸入：無效 CVE ID、None、非字串
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from kits.reporter import generate_report


# ── 共用測試資料 ──────────────────────────────────────────────────────────────

VALID_CVE_ID = "CVE-2021-44228"

EXPECTED_REPORT_KEYS = {
    "cve_id",
    "summary",
    "impact",
    "recommendations",
    "risk_rating",
    "generated_at",
}

VALID_RISK_RATINGS = {"Critical", "High", "Medium", "Low"}

MOCK_CVE_DATA = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 JNDI remote code execution vulnerability.",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "published": "2021-12-10",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    "affected_packages": [{"name": "log4j-core", "version": "2.0-beta9 to 2.14.1"}],
}

MOCK_ANALYSIS = {
    "impact_summary": "Allows unauthenticated remote code execution via JNDI lookup.",
    "attack_vector": "Network",
    "attack_conditions": "No authentication required.",
    "severity_label": "Critical",
    "exploitability": "Actively exploited in the wild.",
    "affected_components": ["log4j-core 2.0-beta9 to 2.14.1"],
}

MOCK_RECOMMENDATION = {
    "patch_actions": ["升級 log4j-core 至 2.17.1 以上"],
    "workarounds": ["設定 log4j2.formatMsgNoLookups=true"],
    "language_specific": {"java": "更新 pom.xml 中的 log4j-core 版本"},
    "priority": "Immediate",
}


# ── 單元測試（全 mock）────────────────────────────────────────────────────────

class TestGenerateReportUnit:
    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_returns_dict_with_required_keys(
        self, mock_fetch, mock_analyze, mock_recommend
    ):
        result = generate_report(VALID_CVE_ID)
        assert isinstance(result, dict)
        assert EXPECTED_REPORT_KEYS.issubset(result.keys())

    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_cve_id_matches_input(self, mock_fetch, mock_analyze, mock_recommend):
        result = generate_report(VALID_CVE_ID)
        assert result["cve_id"] == VALID_CVE_ID

    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_risk_rating_is_valid(self, mock_fetch, mock_analyze, mock_recommend):
        result = generate_report(VALID_CVE_ID)
        assert result["risk_rating"] in VALID_RISK_RATINGS

    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_generated_at_is_iso_datetime_string(
        self, mock_fetch, mock_analyze, mock_recommend
    ):
        result = generate_report(VALID_CVE_ID)
        generated_at = result["generated_at"]
        assert isinstance(generated_at, str)
        # 應可被解析為合法 datetime
        datetime.fromisoformat(generated_at)

    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_pipeline_called_in_order(self, mock_fetch, mock_analyze, mock_recommend):
        generate_report(VALID_CVE_ID)
        mock_fetch.assert_called_once_with(VALID_CVE_ID)
        mock_analyze.assert_called_once_with(MOCK_CVE_DATA)
        mock_recommend.assert_called_once_with(MOCK_CVE_DATA, MOCK_ANALYSIS)

    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_summary_is_nonempty_string(self, mock_fetch, mock_analyze, mock_recommend):
        result = generate_report(VALID_CVE_ID)
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_impact_and_recommendations_are_dicts(
        self, mock_fetch, mock_analyze, mock_recommend
    ):
        result = generate_report(VALID_CVE_ID)
        assert isinstance(result["impact"], dict)
        assert isinstance(result["recommendations"], dict)


# ── 邊界情境 ──────────────────────────────────────────────────────────────────

class TestGenerateReportBoundary:
    @patch("kits.reporter.fetch_cve", side_effect=ValueError("CVE not found"))
    def test_propagates_value_error_from_fetcher(self, mock_fetch):
        with pytest.raises(ValueError):
            generate_report(VALID_CVE_ID)

    @patch(
        "kits.reporter.analyze_cve",
        side_effect=Exception("Claude API error"),
    )
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_propagates_exception_from_analyzer(self, mock_fetch, mock_analyze):
        with pytest.raises(Exception):
            generate_report(VALID_CVE_ID)

    @patch(
        "kits.reporter.generate_recommendation",
        side_effect=Exception("Claude API error"),
    )
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_propagates_exception_from_recommender(
        self, mock_fetch, mock_analyze, mock_recommend
    ):
        with pytest.raises(Exception):
            generate_report(VALID_CVE_ID)


# ── 錯誤輸入 ──────────────────────────────────────────────────────────────────

class TestGenerateReportInvalidInput:
    def test_raises_for_none_input(self):
        with pytest.raises((ValueError, TypeError)):
            generate_report(None)

    def test_raises_for_empty_string(self):
        with pytest.raises((ValueError, TypeError)):
            generate_report("")

    def test_raises_for_malformed_cve_id(self):
        with pytest.raises((ValueError, TypeError)):
            generate_report("NOT-A-CVE")

    def test_raises_for_non_string_input(self):
        with pytest.raises((ValueError, TypeError)):
            generate_report(12345)


# ── threat_intel 參數測試 ─────────────────────────────────────────────────────

MOCK_POC_RESULT = {"has_poc": True, "poc_count": 12}
MOCK_KEV_RESULT = {"in_the_wild": True}


class TestGenerateReportThreatIntel:
    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_no_threat_intel_field_when_both_false(
        self, mock_fetch, mock_analyze, mock_recommend
    ):
        """check_poc=False, check_kev=False → 報告不含 threat_intel 欄位。"""
        result = generate_report(VALID_CVE_ID, check_poc=False, check_kev=False)
        assert "threat_intel" not in result

    @patch("kits.reporter.check_poc_fn", return_value=MOCK_POC_RESULT)
    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_threat_intel_has_poc_when_check_poc_true(
        self, mock_fetch, mock_analyze, mock_recommend, mock_poc
    ):
        """check_poc=True → 報告含 threat_intel.has_poc，無 in_the_wild。"""
        result = generate_report(VALID_CVE_ID, check_poc=True, check_kev=False)
        assert "threat_intel" in result
        assert "has_poc" in result["threat_intel"]
        assert "in_the_wild" not in result["threat_intel"]

    @patch("kits.reporter.check_kev_fn", return_value=MOCK_KEV_RESULT)
    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_threat_intel_has_kev_when_check_kev_true(
        self, mock_fetch, mock_analyze, mock_recommend, mock_kev
    ):
        """check_kev=True → 報告含 threat_intel.in_the_wild，無 has_poc。"""
        result = generate_report(VALID_CVE_ID, check_poc=False, check_kev=True)
        assert "threat_intel" in result
        assert "in_the_wild" in result["threat_intel"]
        assert "has_poc" not in result["threat_intel"]

    @patch("kits.reporter.check_kev_fn", return_value=MOCK_KEV_RESULT)
    @patch("kits.reporter.check_poc_fn", return_value=MOCK_POC_RESULT)
    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_threat_intel_complete_when_both_true(
        self, mock_fetch, mock_analyze, mock_recommend, mock_poc, mock_kev
    ):
        """check_poc=True, check_kev=True → 報告含完整 threat_intel。"""
        result = generate_report(VALID_CVE_ID, check_poc=True, check_kev=True)
        assert "threat_intel" in result
        assert "has_poc" in result["threat_intel"]
        assert "in_the_wild" in result["threat_intel"]

    @patch("kits.reporter.generate_recommendation", return_value=MOCK_RECOMMENDATION)
    @patch("kits.reporter.analyze_cve", return_value=MOCK_ANALYSIS)
    @patch("kits.reporter.fetch_cve", return_value=MOCK_CVE_DATA)
    def test_default_params_no_threat_intel(
        self, mock_fetch, mock_analyze, mock_recommend
    ):
        """預設不帶參數 → 不含 threat_intel（向下相容）。"""
        result = generate_report(VALID_CVE_ID)
        assert "threat_intel" not in result


# ── 整合測試（需要網路）──────────────────────────────────────────────────────

@pytest.mark.integration
class TestGenerateReportIntegration:
    """
    這些測試會真實呼叫外部 API 與 Claude API。
    執行時需設定環境變數：ANTHROPIC_API_KEY
    執行指令：pytest -m integration
    """

    def test_real_log4shell_cve(self):
        result = generate_report("CVE-2021-44228")
        assert isinstance(result, dict)
        assert EXPECTED_REPORT_KEYS.issubset(result.keys())
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["risk_rating"] in VALID_RISK_RATINGS

    def test_real_report_summary_mentions_log4j(self):
        result = generate_report("CVE-2021-44228")
        summary_lower = result["summary"].lower()
        assert any(
            keyword in summary_lower
            for keyword in ["log4j", "log4shell", "jndi", "rce", "remote"]
        )
