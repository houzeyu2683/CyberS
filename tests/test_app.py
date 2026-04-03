"""
測試 app.py — analyze(cve_id, check_poc, check_kev, check_epss) -> dict
           — to_markdown(report_json) -> (str, gr.update)
           — demo (gr.Blocks) UI 結構

測試範圍：
- 正常輸入：合法 CVE ID → 回傳含必要欄位的 dict
- check_poc / check_kev / check_epss 參數傳遞至 generate_report
- 錯誤輸入：非法格式 → {"error": "..."}
- 錯誤輸入：空字串 → {"error": "..."}
- 邊界情境：generate_report 拋出例外 → {"error": "..."}
- to_markdown：有效 report → md 字串含標題，dl_btn visible=True
- to_markdown：None 或含 error → 提示文字，dl_btn visible=False
- UI 結構：demo 包含 gr.Markdown、gr.Textbox、gr.Checkbox x3、gr.JSON
"""

import gradio as gr
import pytest
from unittest.mock import patch, MagicMock
from app import analyze, to_markdown, demo


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
        analyze("CVE-2021-44228", False, False, False)
        mock_report.assert_called_once_with(
            "CVE-2021-44228", check_poc=False, check_kev=False, check_epss=False
        )

    @patch("app.generate_report")
    def test_passes_check_poc_true_to_report(self, mock_report):
        """check_poc=True 應傳遞給 generate_report。"""
        mock_report.return_value = {**MOCK_REPORT, "threat_intel": {"has_poc": True, "poc_count": 3}}
        result = analyze("CVE-2021-44228", True, False, False)
        mock_report.assert_called_once_with(
            "CVE-2021-44228", check_poc=True, check_kev=False, check_epss=False
        )
        assert isinstance(result, dict)

    @patch("app.generate_report")
    def test_passes_check_kev_true_to_report(self, mock_report):
        """check_kev=True 應傳遞給 generate_report。"""
        mock_report.return_value = {**MOCK_REPORT, "threat_intel": {"in_the_wild": True}}
        result = analyze("CVE-2021-44228", False, True, False)
        mock_report.assert_called_once_with(
            "CVE-2021-44228", check_poc=False, check_kev=True, check_epss=False
        )
        assert isinstance(result, dict)

    @patch("app.generate_report")
    def test_passes_both_true_to_report(self, mock_report):
        """check_poc=True, check_kev=True 兩者都傳遞給 generate_report。"""
        threat = {"has_poc": True, "poc_count": 3, "in_the_wild": True}
        mock_report.return_value = {**MOCK_REPORT, "threat_intel": threat}
        result = analyze("CVE-2021-44228", True, True, False)
        mock_report.assert_called_once_with(
            "CVE-2021-44228", check_poc=True, check_kev=True, check_epss=False
        )
        assert "threat_intel" in result


# ── 錯誤輸入 ──────────────────────────────────────────────────────────────────

class TestAnalyzeInvalidInput:
    def test_invalid_format_returns_error_dict(self):
        result = analyze("abc", False, False)
        assert isinstance(result, dict)
        assert "error" in result
        assert isinstance(result["error"], str)
        assert len(result["error"]) > 0

    def test_empty_string_returns_error_dict(self):
        result = analyze("", False, False)
        assert isinstance(result, dict)
        assert "error" in result
        assert isinstance(result["error"], str)

    def test_none_input_returns_error_dict(self):
        result = analyze(None, False, False)
        assert isinstance(result, dict)
        assert "error" in result

    def test_numeric_input_returns_error_dict(self):
        result = analyze("12345", False, False)
        assert isinstance(result, dict)
        assert "error" in result

    def test_invalid_format_no_exception_propagated(self):
        """analyze 不應拋出例外，所有錯誤都應包在 {"error": ...} 中。"""
        try:
            result = analyze("not-a-cve", False, False)
            assert "error" in result
        except Exception as e:
            pytest.fail(f"analyze() raised an exception: {e}")


# ── 邊界情境 ──────────────────────────────────────────────────────────────────

class TestAnalyzeBoundary:
    @patch("app.generate_report", side_effect=Exception("fetch failed"))
    def test_generate_report_exception_returns_error_dict(self, mock_report):
        """generate_report 拋出例外時，應回傳 {"error": ...}。"""
        result = analyze("CVE-2021-44228", False, False)
        assert isinstance(result, dict)
        assert "error" in result
        assert "fetch failed" in result["error"]

    @patch("app.generate_report", side_effect=ValueError("invalid cve"))
    def test_value_error_from_report_returns_error_dict(self, mock_report):
        result = analyze("CVE-2021-44228", False, False)
        assert "error" in result

    @patch("app.generate_report", side_effect=KeyError("missing key"))
    def test_key_error_from_report_returns_error_dict(self, mock_report):
        result = analyze("CVE-2021-44228", False, False)
        assert "error" in result

    @patch("app.generate_report")
    def test_whitespace_only_input_returns_error_dict(self, mock_report):
        result = analyze("   ", False, False)
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

    def test_demo_contains_two_checkbox_components(self):
        """demo 應包含兩個 gr.Checkbox 元件（PoC + KEV）。"""
        components = self._get_all_components()
        checkboxes = [c for c in components if isinstance(c, gr.Checkbox)]
        assert len(checkboxes) >= 2, f"demo 應有 2 個 Checkbox，實際有 {len(checkboxes)} 個"

    def test_checkbox_poc_label(self):
        """其中一個 Checkbox 應與 PoC 偵測相關。"""
        components = self._get_all_components()
        checkboxes = [c for c in components if isinstance(c, gr.Checkbox)]
        labels = [c.label for c in checkboxes if c.label]
        assert any("PoC" in label for label in labels), f"找不到 PoC Checkbox，labels={labels}"

    def test_checkbox_kev_label(self):
        """其中一個 Checkbox 應與 KEV / In the Wild 相關。"""
        components = self._get_all_components()
        checkboxes = [c for c in components if isinstance(c, gr.Checkbox)]
        labels = [c.label for c in checkboxes if c.label]
        assert any(
            "KEV" in label or "Wild" in label or "wild" in label for label in labels
        ), f"找不到 KEV Checkbox，labels={labels}"

    def test_checkboxes_default_to_false(self):
        """所有 Checkbox 預設值應為 False。"""
        components = self._get_all_components()
        checkboxes = [c for c in components if isinstance(c, gr.Checkbox)]
        for cb in checkboxes:
            assert cb.value is False, f"Checkbox '{cb.label}' 預設值應為 False，實際為 {cb.value}"

    def test_demo_contains_three_checkbox_components(self):
        """demo 應包含三個 gr.Checkbox 元件（PoC + KEV + EPSS）。"""
        components = self._get_all_components()
        checkboxes = [c for c in components if isinstance(c, gr.Checkbox)]
        assert len(checkboxes) >= 3, f"demo 應有 3 個 Checkbox，實際有 {len(checkboxes)} 個"

    def test_checkbox_epss_label(self):
        """其中一個 Checkbox 應與 EPSS 偵測相關。"""
        components = self._get_all_components()
        checkboxes = [c for c in components if isinstance(c, gr.Checkbox)]
        labels = [c.label for c in checkboxes if c.label]
        assert any("EPSS" in label for label in labels), f"找不到 EPSS Checkbox，labels={labels}"

    def test_demo_contains_download_button(self):
        """demo 應包含 gr.DownloadButton 元件。"""
        components = self._get_all_components()
        download_btns = [c for c in components if isinstance(c, gr.DownloadButton)]
        assert len(download_btns) >= 1, "demo 中找不到 gr.DownloadButton 元件"

    def test_demo_contains_markdown_report_button(self):
        """demo 應包含「產生 Markdown 報告」按鈕。"""
        components = self._get_all_components()
        buttons = [c for c in components if isinstance(c, gr.Button)]
        labels = [c.value for c in buttons if c.value]
        assert any("Markdown" in label for label in labels), f"找不到 Markdown 報告按鈕，labels={labels}"


# ── EPSS 參數傳遞測試 ─────────────────────────────────────────────────────────

MOCK_REPORT_WITH_EPSS_WARNING = {
    **MOCK_REPORT,
    "threat_intel": {
        "epss_score": 0.15,
        "epss_percentile": 0.95,
        "epss_high_risk": True,
    },
    "epss_warning": "高風險：EPSS 分數 0.1500，超過門檻 0.1，建議優先處理",
}


class TestAnalyzeWithEpss:
    @patch("app.generate_report")
    def test_analyze_with_epss_true(self, mock_report):
        """check_epss=True, mock 高風險 → 回傳含 epss_warning"""
        mock_report.return_value = MOCK_REPORT_WITH_EPSS_WARNING
        result = analyze("CVE-2021-44228", False, False, True)
        mock_report.assert_called_once_with(
            "CVE-2021-44228", check_poc=False, check_kev=False, check_epss=True
        )
        assert "epss_warning" in result

    @patch("app.generate_report")
    def test_analyze_with_epss_false(self, mock_report):
        """check_epss=False → 回傳不含 epss 欄位"""
        mock_report.return_value = MOCK_REPORT
        result = analyze("CVE-2021-44228", False, False, False)
        mock_report.assert_called_once_with(
            "CVE-2021-44228", check_poc=False, check_kev=False, check_epss=False
        )
        assert "epss_warning" not in result
        if "threat_intel" in result:
            assert "epss_score" not in result["threat_intel"]


# ── to_markdown 測試 ──────────────────────────────────────────────────────────

class TestToMarkdown:
    def test_to_markdown_valid_report(self):
        """傳入有效 report dict → 回傳 md 字串含標題，dl_btn visible=True"""
        md_text, dl_update = to_markdown(MOCK_REPORT)
        assert isinstance(md_text, str)
        assert "# CVE 漏洞分析報告" in md_text
        assert dl_update.get("visible") is True

    def test_to_markdown_no_report_none(self):
        """傳入 None → 回傳提示文字，dl_btn visible=False"""
        md_text, dl_update = to_markdown(None)
        assert isinstance(md_text, str)
        assert "尚無報告" in md_text or "請先執行分析" in md_text
        assert dl_update.get("visible") is False

    def test_to_markdown_error_report(self):
        """傳入含 error 的 dict → 回傳提示文字，dl_btn visible=False"""
        md_text, dl_update = to_markdown({"error": "fetch failed"})
        assert isinstance(md_text, str)
        assert dl_update.get("visible") is False

    def test_to_markdown_creates_file(self, tmp_path):
        """呼叫後應在 /tmp/cve_report.md 建立檔案"""
        import os
        to_markdown(MOCK_REPORT)
        assert os.path.exists("/tmp/cve_report.md")
