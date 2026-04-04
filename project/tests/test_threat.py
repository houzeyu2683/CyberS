"""
測試 kits/threat.py — check_poc(cve_id: str) -> dict
                     check_kev(cve_id: str) -> dict
                     check_epss(cve_id: str) -> dict

測試範圍：
- check_poc：正常回傳、有 PoC、無 PoC、GITHUB_TOKEN 選填、連線失敗
- check_kev：正常回傳、在 KEV 清單、不在 KEV 清單、連線失敗
- check_epss：低風險、高風險、查無資料、requests 例外
- 錯誤輸入：None、非字串
"""

import pytest
from unittest.mock import patch, MagicMock
from kits.threat import check_poc, check_kev, check_epss


# ── check_poc ─────────────────────────────────────────────────────────────────

class TestCheckPocNormal:
    @patch("kits.threat.requests.get")
    def test_returns_dict_with_required_keys(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"total_count": 12, "items": []}
        result = check_poc("CVE-2021-44228")
        assert isinstance(result, dict)
        assert "has_poc" in result
        assert "poc_count" in result

    @patch("kits.threat.requests.get")
    def test_has_poc_true_when_total_count_positive(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"total_count": 12, "items": []}
        result = check_poc("CVE-2021-44228")
        assert result["has_poc"] is True
        assert result["poc_count"] == 12

    @patch("kits.threat.requests.get")
    def test_has_poc_false_when_total_count_zero(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"total_count": 0, "items": []}
        result = check_poc("CVE-9999-99999")
        assert result["has_poc"] is False
        assert result["poc_count"] == 0

    @patch("kits.threat.requests.get")
    def test_calls_github_search_api(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"total_count": 0, "items": []}
        check_poc("CVE-2021-44228")
        called_url = mock_get.call_args[0][0]
        assert "api.github.com/search/repositories" in called_url
        assert "CVE-2021-44228" in called_url

    @patch("kits.threat.requests.get")
    def test_includes_github_token_in_header_when_available(self, mock_get):
        """GITHUB_TOKEN 存在時應加入 Authorization header。"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"total_count": 0, "items": []}
        with patch("kits.threat.GITHUB_TOKEN", "fake-token-123"):
            check_poc("CVE-2021-44228")
        headers = mock_get.call_args[1].get("headers", {})
        assert "Authorization" in headers
        assert "fake-token-123" in headers["Authorization"]

    @patch("kits.threat.requests.get")
    def test_no_auth_header_when_token_absent(self, mock_get):
        """GITHUB_TOKEN 不存在時不應加入 Authorization header。"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"total_count": 0, "items": []}
        with patch("kits.threat.GITHUB_TOKEN", None):
            check_poc("CVE-2021-44228")
        headers = mock_get.call_args[1].get("headers", {})
        assert "Authorization" not in headers


class TestCheckPocError:
    @patch("kits.threat.requests.get", side_effect=ConnectionError("network error"))
    def test_raises_connection_error_on_api_failure(self, mock_get):
        with pytest.raises(ConnectionError):
            check_poc("CVE-2021-44228")

    @patch("kits.threat.requests.get", side_effect=Exception("timeout"))
    def test_raises_on_request_exception(self, mock_get):
        with pytest.raises(Exception):
            check_poc("CVE-2021-44228")


# ── check_kev ─────────────────────────────────────────────────────────────────

MOCK_KEV_RESPONSE = {
    "title": "CISA KEV",
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
        {"cveID": "CVE-2021-45046", "vendorProject": "Apache"},
    ],
}

MOCK_KEV_RESPONSE_EMPTY = {
    "title": "CISA KEV",
    "vulnerabilities": [],
}


class TestCheckKevNormal:
    @patch("kits.threat.requests.get")
    def test_returns_dict_with_in_the_wild_key(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        result = check_kev("CVE-2021-44228")
        assert isinstance(result, dict)
        assert "in_the_wild" in result

    @patch("kits.threat.requests.get")
    def test_in_the_wild_true_when_cve_in_kev(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        result = check_kev("CVE-2021-44228")
        assert result["in_the_wild"] is True

    @patch("kits.threat.requests.get")
    def test_in_the_wild_false_when_cve_not_in_kev(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        result = check_kev("CVE-9999-99999")
        assert result["in_the_wild"] is False

    @patch("kits.threat.requests.get")
    def test_in_the_wild_false_when_kev_empty(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE_EMPTY
        result = check_kev("CVE-2021-44228")
        assert result["in_the_wild"] is False

    @patch("kits.threat.requests.get")
    def test_calls_cisa_kev_url(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        check_kev("CVE-2021-44228")
        called_url = mock_get.call_args[0][0]
        assert "cisa.gov" in called_url
        assert "known_exploited_vulnerabilities" in called_url

    @patch("kits.threat.requests.get")
    def test_case_insensitive_cve_matching(self, mock_get):
        """CVE ID 比對應不分大小寫。"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        result = check_kev("cve-2021-44228")
        assert result["in_the_wild"] is True


class TestCheckKevError:
    @patch("kits.threat.requests.get", side_effect=ConnectionError("network error"))
    def test_raises_connection_error_on_api_failure(self, mock_get):
        with pytest.raises(ConnectionError):
            check_kev("CVE-2021-44228")

    @patch("kits.threat.requests.get", side_effect=Exception("timeout"))
    def test_raises_on_request_exception(self, mock_get):
        with pytest.raises(Exception):
            check_kev("CVE-2021-44228")


# ── check_epss ────────────────────────────────────────────────────────────────

MOCK_EPSS_RESPONSE_LOW = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 1,
    "offset": 0,
    "limit": 100,
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.03", "percentile": "0.5", "date": "2024-01-01"}
    ],
}

MOCK_EPSS_RESPONSE_HIGH = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 1,
    "offset": 0,
    "limit": 100,
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.15", "percentile": "0.95", "date": "2024-01-01"}
    ],
}

MOCK_EPSS_RESPONSE_EMPTY = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 0,
    "offset": 0,
    "limit": 100,
    "data": [],
}


class TestCheckEpss:
    @patch("kits.threat.requests.get")
    def test_check_epss_found_low_risk(self, mock_get):
        """score=0.03 → epss_score=0.03, epss_high_risk=False"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE_LOW
        result = check_epss("CVE-2021-44228")
        assert isinstance(result, dict)
        assert "epss_score" in result
        assert "epss_percentile" in result
        assert "epss_high_risk" in result
        assert abs(result["epss_score"] - 0.03) < 1e-9
        assert result["epss_high_risk"] is False

    @patch("kits.threat.requests.get")
    def test_check_epss_found_high_risk(self, mock_get):
        """score=0.15 → epss_score=0.15, epss_high_risk=True"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE_HIGH
        result = check_epss("CVE-2021-44228")
        assert result["epss_score"] == pytest.approx(0.15)
        assert result["epss_high_risk"] is True

    @patch("kits.threat.requests.get")
    def test_check_epss_not_found(self, mock_get):
        """API 回傳空 data 陣列 → epss_score=None, epss_note='無資料'"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE_EMPTY
        result = check_epss("CVE-9999-99999")
        assert result["epss_score"] is None
        assert result["epss_percentile"] is None
        assert result["epss_high_risk"] is False
        assert result.get("epss_note") == "無資料"

    @patch("kits.threat.requests.get", side_effect=Exception("timeout"))
    def test_check_epss_request_exception(self, mock_get):
        """requests 拋出 Exception → 回傳無資料結構，不往外拋"""
        result = check_epss("CVE-2021-44228")
        assert result["epss_score"] is None
        assert result["epss_percentile"] is None
        assert result["epss_high_risk"] is False
        assert result.get("epss_note") == "無資料"

    @patch("kits.threat.requests.get")
    def test_check_epss_calls_first_api(self, mock_get):
        """應呼叫 FIRST EPSS API"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE_LOW
        check_epss("CVE-2021-44228")
        called_url = mock_get.call_args[0][0]
        assert "api.first.org" in called_url
        assert "CVE-2021-44228" in called_url

    @patch("kits.threat.requests.get")
    def test_check_epss_percentile_correct(self, mock_get):
        """回傳的 epss_percentile 應對應 API 資料"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE_LOW
        result = check_epss("CVE-2021-44228")
        assert result["epss_percentile"] == pytest.approx(0.5)
