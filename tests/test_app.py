"""
測試 app.py — analyze(cve_id: str) -> dict
           — demo (gr.Blocks) UI 結構

測試範圍：
- 正常輸入：合法 CVE ID → 回傳含必要欄位的 dict
- 錯誤輸入：非法格式 → {"error": "..."}
- 錯誤輸入：空字串 → {"error": "..."}
- 邊界情境：generate_report 拋出例外 → {"error": "..."}
- UI 結構：demo 包含 gr.Markdown、gr.Textbox、gr.JSON
"""

import gradio as gr
import pytest
from unittest.mock import patch, MagicMock
from app import analyze, demo


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


# ── UI 結構測試 ───────────────────────────────────────────────────────────────

class TestAppUIStructure:
    def _get_all_components(self):
        """取得 demo.blocks 中所有 component 物件。"""
        return list(demo.blocks.values())

    def test_demo_is_gradio_blocks(self):
        """demo 應為 gr.Blocks 實例。"""
        assert isinstance(demo, gr.Blocks)

    def test_demo_contains_markdown_component(self):
        """demo 應包含至少一個 gr.Markdown 元件。"""
        components = self._get_all_components()
        markdown_components = [c for c in components if isinstance(c, gr.Markdown)]
        assert len(markdown_components) >= 1, "demo 中找不到 gr.Markdown 元件"

    def test_demo_contains_textbox_component(self):
        """demo 應包含 gr.Textbox 元件。"""
        components = self._get_all_components()
        textboxes = [c for c in components if isinstance(c, gr.Textbox)]
        assert len(textboxes) >= 1, "demo 中找不到 gr.Textbox 元件"

    def test_demo_contains_json_component(self):
        """demo 應包含 gr.JSON 元件。"""
        components = self._get_all_components()
        json_components = [c for c in components if isinstance(c, gr.JSON)]
        assert len(json_components) >= 1, "demo 中找不到 gr.JSON 元件"

    def test_markdown_contains_project_title(self):
        """Markdown 元件應包含標題「CVE 自動分析系統」。"""
        components = self._get_all_components()
        markdown_components = [c for c in components if isinstance(c, gr.Markdown)]
        all_text = " ".join(c.value for c in markdown_components if c.value)
        assert "CVE 自動分析系統" in all_text

    def test_markdown_contains_usage_flow(self):
        """Markdown 元件應包含「使用流程」說明。"""
        components = self._get_all_components()
        markdown_components = [c for c in components if isinstance(c, gr.Markdown)]
        all_text = " ".join(c.value for c in markdown_components if c.value)
        assert "使用流程" in all_text

    def test_markdown_contains_three_steps(self):
        """Markdown 元件應包含三個步驟說明（1. 2. 3.）。"""
        components = self._get_all_components()
        markdown_components = [c for c in components if isinstance(c, gr.Markdown)]
        all_text = " ".join(c.value for c in markdown_components if c.value)
        assert "1." in all_text
        assert "2." in all_text
        assert "3." in all_text

    def test_markdown_mentions_project_purpose(self):
        """Markdown 元件應包含「專案用途」說明。"""
        components = self._get_all_components()
        markdown_components = [c for c in components if isinstance(c, gr.Markdown)]
        all_text = " ".join(c.value for c in markdown_components if c.value)
        assert "專案用途" in all_text

    def test_textbox_label_is_cve_id(self):
        """Textbox 的 label 應為 'CVE ID'。"""
        components = self._get_all_components()
        textboxes = [c for c in components if isinstance(c, gr.Textbox)]
        labels = [c.label for c in textboxes]
        assert "CVE ID" in labels

    def test_textbox_placeholder_contains_example(self):
        """Textbox 的 placeholder 應包含 CVE ID 範例。"""
        components = self._get_all_components()
        textboxes = [c for c in components if isinstance(c, gr.Textbox)]
        placeholders = [c.placeholder for c in textboxes if c.placeholder]
        assert any("CVE-" in p for p in placeholders)
