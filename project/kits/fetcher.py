"""
kits/fetcher.py — CVE 資料擷取

fetch_cve(cve_id: str) -> dict
資料來源優先順序：NVD API → OSV.dev → GitHub Advisory
"""

import re
import requests

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_URL = "https://api.osv.dev/v1/query"
GITHUB_ADVISORY_URL = "https://api.github.com/graphql"


def _validate_cve_id(cve_id):
    if cve_id is None:
        raise TypeError("cve_id must be a string, got None")
    if not isinstance(cve_id, str):
        raise TypeError(f"cve_id must be a string, got {type(cve_id).__name__}")
    if not cve_id.strip():
        raise ValueError("cve_id must not be empty")
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id!r}")


def fetch_from_nvd(cve_id: str):
    """查詢 NVD API，回傳標準化 dict 或 None。"""
    try:
        resp = requests.get(NVD_API_URL, params={"cveId": cve_id}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # [ 
        #   'resultsPerPage', 漏洞資料本體	
        #   'startIndex', 這次回傳幾筆	
        #   'totalResults', 從第幾筆開始	
        #   'format', 總共有幾筆	
        #   'version', 回傳格式名稱	
        #   'timestamp', API 版本號	
        #   'vulnerabilities' 查詢時間	
        # ]
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        item = vulnerabilities[0]["cve"]
        descriptions = item.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )
        metrics = item.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break
        published = item.get("published", "")[:10]
        references = [
            r["url"] for r in item.get("references", []) if "url" in r
        ]
        configurations = item.get("configurations", [])
        affected_packages = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    uri = cpe.get("criteria", "")
                    parts = uri.split(":")
                    if len(parts) >= 5:
                        affected_packages.append({
                            "name": parts[4],
                            "version": cpe.get("versionEndIncluding", parts[5] if len(parts) > 5 else ""),
                        })
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "published": published,
            "references": references,
            "affected_packages": affected_packages,
        }
    except (requests.RequestException, KeyError, IndexError, ValueError) as e:
        raise ConnectionError(f"NVD API error: {e}") from e


def fetch_from_osv(cve_id: str):
    """查詢 OSV.dev API，回傳標準化 dict 或 None。"""
    try:
        resp = requests.post(
            OSV_API_URL,
            json={"query": {"id": cve_id}},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulns", [])
        if not vulns:
            return None
        vuln = vulns[0]
        description = vuln.get("details", vuln.get("summary", ""))
        severity_list = vuln.get("severity", [])
        cvss_score = None
        cvss_vector = None
        for sev in severity_list:
            if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
                cvss_vector = sev.get("score")
                break
        published = vuln.get("published", "")[:10]
        references = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]
        affected_packages = []
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            name = pkg.get("name", "")
            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    if "fixed" in event:
                        affected_packages.append({"name": name, "version": event["fixed"]})
                        break
                else:
                    if name:
                        affected_packages.append({"name": name, "version": ""})
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "published": published,
            "references": references,
            "affected_packages": affected_packages,
        }
    except (requests.RequestException, KeyError, ValueError) as e:
        raise ConnectionError(f"OSV API error: {e}") from e


def fetch_from_github_advisory(cve_id: str):
    """查詢 GitHub Advisory Database，回傳標準化 dict 或 None。"""
    try:
        query = """
        query($cveId: String!) {
          securityVulnerabilities(first: 1, query: $cveId) {
            nodes {
              advisory {
                identifiers { type value }
                description
                cvss { score vectorString }
                publishedAt
                references { url }
              }
              package { name }
              vulnerableVersionRange
            }
          }
        }
        """
        import os
        token = os.environ.get("GITHUB_TOKEN", "")
        headers = {"Authorization": f"bearer {token}"} if token else {}
        resp = requests.post(
            GITHUB_ADVISORY_URL,
            json={"query": query, "variables": {"cveId": cve_id}},
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
        if not nodes:
            return None
        node = nodes[0]
        advisory = node.get("advisory", {})
        description = advisory.get("description", "")
        cvss = advisory.get("cvss") or {}
        cvss_score = cvss.get("score")
        cvss_vector = cvss.get("vectorString")
        published = (advisory.get("publishedAt") or "")[:10]
        references = [r["url"] for r in advisory.get("references", []) if r.get("url")]
        pkg_name = node.get("package", {}).get("name", "")
        version_range = node.get("vulnerableVersionRange", "")
        affected_packages = [{"name": pkg_name, "version": version_range}] if pkg_name else []
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "published": published,
            "references": references,
            "affected_packages": affected_packages,
        }
    except (requests.RequestException, KeyError, ValueError) as e:
        raise ConnectionError(f"GitHub Advisory API error: {e}") from e


def fetch_cve(cve_id: str) -> dict:
    """
    擷取 CVE 資料。優先順序：NVD → OSV → GitHub Advisory。
    若所有來源都無資料，raise ValueError。
    """
    _validate_cve_id(cve_id)

    result = None
    try:
        result = fetch_from_nvd(cve_id)
    except (ConnectionError, Exception):
        pass

    if result is None:
        try:
            result = fetch_from_osv(cve_id)
        except (ConnectionError, Exception):
            pass

    if result is None:
        try:
            result = fetch_from_github_advisory(cve_id)
        except (ConnectionError, Exception):
            pass

    if result is None:
        raise ValueError(f"CVE not found in any source: {cve_id}")

    return result
