"""
測試 kits/analyzer.py — analyze_cve(cve_data: dict) -> dict
                        call_llm(prompt: str, system_prompt: str) -> dict

測試範圍：
- 正常輸入：完整 cve_data，回傳完整分析 dict
- 邊界情境：LLM API 回空回應、LLM API 例外
- 錯誤輸入：cve_data 缺少關鍵欄位、傳入 None / 非 dict
- call_llm：正確呼叫 Gemini API、key.yaml 缺失、GOOGLE_API_KEY 缺失
"""

import json
import sys
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

MOCK_LLM_ANALYSIS = {
    "impact_summary": "Allows unauthenticated remote code execution via JNDI lookup.",
    "attack_vector": "Network",
    "attack_conditions": "No authentication required; vulnerable log4j version in use.",
    "severity_label": "Critical",
    "exploitability": "Actively exploited in the wild.",
    "affected_components": ["log4j-core 2.0-beta9 to 2.14.1"],
}


# ── 正常輸入 ──────────────────────────────────────────────────────────────────

class TestAnalyzeCveNormal:
    @patch("kits.analyzer.call_llm")
    def test_returns_dict_with_required_keys(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert isinstance(result, dict)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.analyzer.call_llm")
    def test_severity_label_is_valid(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert result["severity_label"] in VALID_SEVERITY_LABELS

    @patch("kits.analyzer.call_llm")
    def test_attack_vector_is_valid(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert result["attack_vector"] in VALID_ATTACK_VECTORS

    @patch("kits.analyzer.call_llm")
    def test_affected_components_is_list(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert isinstance(result["affected_components"], list)

    @patch("kits.analyzer.call_llm")
    def test_impact_summary_is_nonempty_string(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
        result = analyze_cve(SAMPLE_CVE_DATA)
        assert isinstance(result["impact_summary"], str)
        assert len(result["impact_summary"]) > 0


# ── 邊界情境 ──────────────────────────────────────────────────────────────────

class TestAnalyzeCveBoundary:
    @patch("kits.analyzer.call_llm")
    def test_handles_empty_references_in_cve_data(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
        data = {**SAMPLE_CVE_DATA, "references": []}
        result = analyze_cve(data)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.analyzer.call_llm")
    def test_handles_empty_affected_packages(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
        data = {**SAMPLE_CVE_DATA, "affected_packages": []}
        result = analyze_cve(data)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.analyzer.call_llm", side_effect=Exception("API timeout"))
    def test_raises_on_llm_api_exception(self, mock_llm):
        with pytest.raises(Exception):
            analyze_cve(SAMPLE_CVE_DATA)

    @patch("kits.analyzer.call_llm", return_value=None)
    def test_raises_or_handles_llm_returning_none(self, mock_llm):
        with pytest.raises((ValueError, TypeError, AttributeError)):
            analyze_cve(SAMPLE_CVE_DATA)

    @patch("kits.analyzer.call_llm")
    def test_handles_minimal_cve_data_with_only_required_fields(self, mock_llm):
        mock_llm.return_value = MOCK_LLM_ANALYSIS
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


# ── call_llm 行為測試 ─────────────────────────────────────────────────────────

class TestCallLlmAnalyzer:
    def _make_mock_client(self, response_text):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = response_text
        mock_client.models.generate_content.return_value = mock_response
        return mock_client

    def test_call_llm_returns_parsed_dict(self):
        from kits.llm import call_llm
        mock_client = self._make_mock_client(json.dumps(MOCK_LLM_ANALYSIS))
        with patch("kits.llm.genai.Client", return_value=mock_client):
            with patch.dict("os.environ", {"GOOGLE_API_KEY": "test_key"}):
                result = call_llm("test prompt", "system prompt")
        assert result == MOCK_LLM_ANALYSIS

    def test_call_llm_uses_gemini_flash_model(self):
        from kits.llm import call_llm
        mock_client = self._make_mock_client(json.dumps(MOCK_LLM_ANALYSIS))
        with patch("kits.llm.genai.Client", return_value=mock_client):
            with patch.dict("os.environ", {"GOOGLE_API_KEY": "test_key"}):
                call_llm("test prompt", "system prompt")
        mock_client.models.generate_content.assert_called_once()
        call_kwargs = mock_client.models.generate_content.call_args
        assert call_kwargs.kwargs.get("model") == "gemini-2.5-flash"

    def test_call_llm_passes_system_instruction(self):
        from kits.llm import call_llm
        mock_client = self._make_mock_client('{"result": "ok"}')
        with patch("kits.llm.genai.Client", return_value=mock_client):
            with patch.dict("os.environ", {"GOOGLE_API_KEY": "test_key"}):
                call_llm("prompt text", "custom system")
        call_kwargs = mock_client.models.generate_content.call_args
        config = call_kwargs.kwargs.get("config")
        assert config.system_instruction == "custom system"

    def test_call_llm_raises_on_api_failure(self):
        from kits.llm import call_llm
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("API error")
        with patch("kits.llm.genai.Client", return_value=mock_client):
            with patch.dict("os.environ", {"GOOGLE_API_KEY": "test_key"}):
                with pytest.raises(Exception, match="API error"):
                    call_llm("prompt", "system")

    def test_missing_google_api_key_raises_error(self):
        from kits.llm import call_llm
        with patch.dict("os.environ", {}, clear=True):
            import os
            os.environ.pop("GOOGLE_API_KEY", None)
            with pytest.raises(EnvironmentError):
                call_llm("prompt", "system")
