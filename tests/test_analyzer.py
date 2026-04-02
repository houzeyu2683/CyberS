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
from unittest.mock import patch, MagicMock, mock_open
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
    def test_call_llm_returns_parsed_dict(self):
        """call_llm 應回傳 JSON 解析後的 dict。"""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps(MOCK_LLM_ANALYSIS)
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict(sys.modules, {"google.generativeai": mock_genai}):
            import importlib
            import kits.analyzer as analyzer_mod
            importlib.reload(analyzer_mod)
            result = analyzer_mod.call_llm("test prompt", "system prompt")

        assert result == MOCK_LLM_ANALYSIS

    def test_call_llm_uses_gemini_flash_model(self):
        """call_llm 應使用 gemini-2.5-flash 模型。"""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps(MOCK_LLM_ANALYSIS)
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict(sys.modules, {"google.generativeai": mock_genai}):
            import importlib
            import kits.analyzer as analyzer_mod
            importlib.reload(analyzer_mod)
            analyzer_mod.call_llm("test prompt", "system prompt")

        mock_genai.GenerativeModel.assert_called_once_with(
            model_name="gemini-2.5-flash",
            system_instruction="system prompt",
        )

    def test_call_llm_passes_system_instruction(self):
        """call_llm 應將 system_prompt 傳入 system_instruction。"""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '{"result": "ok"}'
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict(sys.modules, {"google.generativeai": mock_genai}):
            import importlib
            import kits.analyzer as analyzer_mod
            importlib.reload(analyzer_mod)
            analyzer_mod.call_llm("prompt text", "custom system")

        _, kwargs = mock_genai.GenerativeModel.call_args
        assert kwargs.get("system_instruction") == "custom system"

    def test_call_llm_raises_on_api_failure(self):
        """call_llm 應在 API 失敗時拋出例外。"""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("API error")
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict(sys.modules, {"google.generativeai": mock_genai}):
            import importlib
            import kits.analyzer as analyzer_mod
            importlib.reload(analyzer_mod)
            with pytest.raises(Exception, match="API error"):
                analyzer_mod.call_llm("prompt", "system")

    def test_missing_key_yaml_raises_error(self):
        """key.yaml 不存在時應拋出明確錯誤。"""
        import importlib
        mock_genai = MagicMock()

        with patch.dict(sys.modules, {"google.generativeai": mock_genai}):
            with patch("builtins.open", side_effect=FileNotFoundError("key.yaml not found")):
                with pytest.raises((FileNotFoundError, OSError)):
                    import kits.analyzer as analyzer_mod
                    importlib.reload(analyzer_mod)

    def test_missing_google_api_key_raises_error(self):
        """key.yaml 中缺少 GOOGLE_API_KEY 時應拋出明確錯誤。"""
        import importlib
        import yaml
        mock_genai = MagicMock()
        yaml_content = "OTHER_KEY: some_value\n"

        with patch.dict(sys.modules, {"google.generativeai": mock_genai}):
            with patch("builtins.open", mock_open(read_data=yaml_content)):
                with patch("yaml.safe_load", return_value={"OTHER_KEY": "some_value"}):
                    with pytest.raises(KeyError):
                        import kits.analyzer as analyzer_mod
                        importlib.reload(analyzer_mod)
