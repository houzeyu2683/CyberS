"""
測試 kits/fetcher.py — fetch_cve(cve_id: str) -> dict

測試範圍：
- 正常輸入：合法 CVE ID，回傳完整 dict
- 邊界情境：API 回空回應、網路錯誤
- 錯誤輸入：不存在的 CVE ID（應 raise ValueError）、格式錯誤的 ID
"""

import pytest
from unittest.mock import patch, MagicMock
from kits.fetcher import fetch_cve


# ── 共用測試資料 ──────────────────────────────────────────────────────────────

VALID_CVE_ID = "CVE-2021-44228"

EXPECTED_KEYS = {
    "cve_id",
    "description",
    "cvss_score",
    "cvss_vector",
    "published",
    "references",
    "affected_packages",
}

MOCK_NVD_RESPONSE = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 JNDI remote code execution vulnerability.",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "published": "2021-12-10",
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://logging.apache.org/log4j/2.x/security.html",
    ],
    "affected_packages": [
        {"name": "log4j-core", "version": "2.0-beta9 to 2.14.1"}
    ],
}


# ── 正常輸入 ──────────────────────────────────────────────────────────────────

class TestFetchCveNormal:
    @patch("kits.fetcher.fetch_from_nvd")
    def test_returns_dict_with_required_keys(self, mock_nvd):
        mock_nvd.return_value = MOCK_NVD_RESPONSE
        result = fetch_cve(VALID_CVE_ID)
        assert isinstance(result, dict)
        assert EXPECTED_KEYS.issubset(result.keys())

    @patch("kits.fetcher.fetch_from_nvd")
    def test_cve_id_preserved_in_result(self, mock_nvd):
        mock_nvd.return_value = MOCK_NVD_RESPONSE
        result = fetch_cve(VALID_CVE_ID)
        assert result["cve_id"] == VALID_CVE_ID

    @patch("kits.fetcher.fetch_from_nvd")
    def test_cvss_score_is_float(self, mock_nvd):
        mock_nvd.return_value = MOCK_NVD_RESPONSE
        result = fetch_cve(VALID_CVE_ID)
        assert isinstance(result["cvss_score"], (int, float))

    @patch("kits.fetcher.fetch_from_nvd")
    def test_references_is_list(self, mock_nvd):
        mock_nvd.return_value = MOCK_NVD_RESPONSE
        result = fetch_cve(VALID_CVE_ID)
        assert isinstance(result["references"], list)

    @patch("kits.fetcher.fetch_from_nvd")
    def test_affected_packages_is_list(self, mock_nvd):
        mock_nvd.return_value = MOCK_NVD_RESPONSE
        result = fetch_cve(VALID_CVE_ID)
        assert isinstance(result["affected_packages"], list)


# ── 資料來源 fallback 順序 ────────────────────────────────────────────────────

class TestFetchCveFallback:
    @patch("kits.fetcher.fetch_from_github_advisory")
    @patch("kits.fetcher.fetch_from_osv")
    @patch("kits.fetcher.fetch_from_nvd")
    def test_fallback_to_osv_when_nvd_returns_none(
        self, mock_nvd, mock_osv, mock_github
    ):
        mock_nvd.return_value = None
        mock_osv.return_value = MOCK_NVD_RESPONSE
        result = fetch_cve(VALID_CVE_ID)
        assert result is not None
        mock_osv.assert_called_once()
        mock_github.assert_not_called()

    @patch("kits.fetcher.fetch_from_github_advisory")
    @patch("kits.fetcher.fetch_from_osv")
    @patch("kits.fetcher.fetch_from_nvd")
    def test_fallback_to_github_when_nvd_and_osv_return_none(
        self, mock_nvd, mock_osv, mock_github
    ):
        mock_nvd.return_value = None
        mock_osv.return_value = None
        mock_github.return_value = MOCK_NVD_RESPONSE
        result = fetch_cve(VALID_CVE_ID)
        assert result is not None
        mock_github.assert_called_once()


# ── 邊界情境 ──────────────────────────────────────────────────────────────────

class TestFetchCveBoundary:
    @patch("kits.fetcher.fetch_from_github_advisory")
    @patch("kits.fetcher.fetch_from_osv")
    @patch("kits.fetcher.fetch_from_nvd")
    def test_raises_value_error_when_all_sources_return_none(
        self, mock_nvd, mock_osv, mock_github
    ):
        mock_nvd.return_value = None
        mock_osv.return_value = None
        mock_github.return_value = None
        with pytest.raises(ValueError):
            fetch_cve(VALID_CVE_ID)

    @patch("kits.fetcher.fetch_from_nvd", side_effect=ConnectionError("timeout"))
    def test_handles_network_error_on_nvd(self, mock_nvd):
        """NVD 網路錯誤時，應 fallback 或 raise，不應 crash 無訊息"""
        with pytest.raises((ValueError, ConnectionError)):
            fetch_cve(VALID_CVE_ID)

    @patch("kits.fetcher.fetch_from_nvd")
    def test_result_with_empty_references(self, mock_nvd):
        response = {**MOCK_NVD_RESPONSE, "references": []}
        mock_nvd.return_value = response
        result = fetch_cve(VALID_CVE_ID)
        assert result["references"] == []

    @patch("kits.fetcher.fetch_from_nvd")
    def test_result_with_empty_affected_packages(self, mock_nvd):
        response = {**MOCK_NVD_RESPONSE, "affected_packages": []}
        mock_nvd.return_value = response
        result = fetch_cve(VALID_CVE_ID)
        assert result["affected_packages"] == []


# ── 錯誤輸入 ──────────────────────────────────────────────────────────────────

class TestFetchCveInvalidInput:
    def test_raises_value_error_for_nonexistent_cve(self):
        with pytest.raises(ValueError):
            fetch_cve("CVE-9999-99999")

    def test_raises_for_malformed_cve_id(self):
        with pytest.raises((ValueError, TypeError)):
            fetch_cve("NOT-A-CVE")

    def test_raises_for_empty_string(self):
        with pytest.raises((ValueError, TypeError)):
            fetch_cve("")

    def test_raises_for_none_input(self):
        with pytest.raises((ValueError, TypeError)):
            fetch_cve(None)
