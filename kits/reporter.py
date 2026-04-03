"""
kits/reporter.py — 結構化報告組裝

generate_report(cve_id: str) -> dict
依序呼叫 fetcher → analyzer → recommender，組裝完整報告。
"""

import re
from datetime import datetime

from kits.fetcher import fetch_cve
from kits.analyzer import analyze_cve
from kits.recommender import generate_recommendation
from kits.threat import check_poc as check_poc_fn, check_kev as check_kev_fn, check_epss as check_epss_fn

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

SEVERITY_TO_RISK = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}


def _validate_cve_id(cve_id):
    if cve_id is None:
        raise TypeError("cve_id must be a string, got None")
    if not isinstance(cve_id, str):
        raise TypeError(f"cve_id must be a string, got {type(cve_id).__name__}")
    if not cve_id.strip():
        raise ValueError("cve_id must not be empty")
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id!r}")


def generate_report(cve_id: str, check_poc: bool = False, check_kev: bool = False, check_epss: bool = False) -> dict:
    """
    生成完整 CVE 分析報告。
    """
    _validate_cve_id(cve_id)

    cve_data = fetch_cve(cve_id)
    analysis = analyze_cve(cve_data)
    recommendation = generate_recommendation(cve_data, analysis)

    severity_label = analysis.get("severity_label", "Medium")
    risk_rating = SEVERITY_TO_RISK.get(severity_label, "Medium")

    summary = (
        f"{cve_id}: {cve_data.get('description', '')[:200]}"
        if cve_data.get("description")
        else f"{cve_id} — {analysis.get('impact_summary', '')}"
    )

    threat_intel = {}
    if check_poc:
        threat_intel.update(check_poc_fn(cve_id))
    if check_kev:
        threat_intel.update(check_kev_fn(cve_id))
    if check_epss:
        threat_intel.update(check_epss_fn(cve_id))

    report = {
        "cve_id": cve_id,
        "summary": summary,
        "impact": analysis,
        "recommendations": recommendation,
        "risk_rating": risk_rating,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }
    if threat_intel:
        report["threat_intel"] = threat_intel
        if threat_intel.get("epss_high_risk"):
            score = threat_intel["epss_score"]
            report["epss_warning"] = f"高風險：EPSS 分數 {score:.4f}，超過門檻 0.1，建議優先處理"
    return report


def report_to_markdown(report: dict) -> str:
    """將報告 dict 轉換成人讀 Markdown 字串。"""
    cve_id = report.get("cve_id", "")
    risk_rating = report.get("risk_rating", "")
    generated_at = report.get("generated_at", "")
    summary = report.get("summary", "")
    impact = report.get("impact", {})
    recommendations = report.get("recommendations", {})
    threat_intel = report.get("threat_intel")
    epss_warning = report.get("epss_warning")

    priority = recommendations.get("priority", "")
    patch_actions = recommendations.get("patch_actions", [])
    workarounds = recommendations.get("workarounds", [])

    affected_components = impact.get("affected_components", [])
    components_md = "\n".join(f"  - {c}" for c in affected_components) if affected_components else "  - N/A"

    patch_md = "\n".join(f"{i+1}. {a}" for i, a in enumerate(patch_actions)) if patch_actions else "N/A"
    workaround_md = "\n".join(f"{i+1}. {w}" for i, w in enumerate(workarounds)) if workarounds else "N/A"

    lines = [
        "# CVE 漏洞分析報告",
        "",
        "## 基本資訊",
        f"- **CVE ID**: {cve_id}",
        f"- **風險評級**: {risk_rating}",
        f"- **優先級**: {priority}",
        f"- **產生時間**: {generated_at}",
        "",
        "## 漏洞摘要",
        summary,
        "",
        "## 影響分析",
        f"- **影響摘要**: {impact.get('impact_summary', '')}",
        f"- **攻擊向量**: {impact.get('attack_vector', '')}",
        f"- **攻擊條件**: {impact.get('attack_conditions', '')}",
        f"- **嚴重性**: {impact.get('severity_label', '')}",
        f"- **可利用性**: {impact.get('exploitability', '')}",
        "- **受影響元件**:",
        components_md,
        "",
        "## 修復建議",
        "### 修補行動",
        patch_md,
        "",
        "### 暫時緩解措施",
        workaround_md,
    ]

    if threat_intel:
        lines += ["", "## 威脅情報", ""]
        rows = []
        if "has_poc" in threat_intel:
            poc_count = threat_intel.get("poc_count", 0)
            status = f"是（{poc_count} 個倉庫）" if threat_intel["has_poc"] else "否"
            rows.append(f"| PoC 公開 | {status} |")
        if "in_the_wild" in threat_intel:
            status = "是" if threat_intel["in_the_wild"] else "否"
            rows.append(f"| In the Wild（CISA KEV） | {status} |")
        if "epss_score" in threat_intel:
            if threat_intel["epss_score"] is None:
                rows.append("| EPSS 分數 | 無資料 |")
            else:
                score = threat_intel["epss_score"]
                pct = threat_intel.get("epss_percentile", 0)
                high = " **⚠️ 高風險**" if threat_intel.get("epss_high_risk") else ""
                rows.append(f"| EPSS 分數 | {score:.4f}（百分位：{pct:.1%}）{high} |")

        if rows:
            lines.append("| 指標 | 狀態 |")
            lines.append("|------|------|")
            lines.extend(rows)

    if epss_warning:
        lines += ["", f"> ⚠️ {epss_warning}"]

    return "\n".join(lines)
