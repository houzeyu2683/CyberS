"""
kits/threat.py — 威脅情報查詢

check_poc(cve_id: str) -> dict   GitHub Search API 偵測 PoC
check_kev(cve_id: str) -> dict   CISA KEV 查詢已知在野利用
"""

import requests
import yaml

try:
    with open("key.yaml") as f:
        _keys = yaml.safe_load(f)
    GITHUB_TOKEN = _keys.get("GITHUB_TOKEN")
except FileNotFoundError:
    GITHUB_TOKEN = None


def check_poc(cve_id: str) -> dict:
    """查詢 GitHub 是否有與此 CVE 相關的 PoC 倉庫。"""
    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    url = f"https://api.github.com/search/repositories?q={cve_id}"
    resp = requests.get(url, headers=headers)
    data = resp.json()
    count = data.get("total_count", 0)
    return {"has_poc": count > 0, "poc_count": count}


def check_kev(cve_id: str) -> dict:
    """查詢 CISA KEV 資料庫，確認 CVE 是否已知在野利用。"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url)
    vulns = resp.json().get("vulnerabilities", [])
    found = any(v.get("cveID", "").upper() == cve_id.upper() for v in vulns)
    return {"in_the_wild": found}
