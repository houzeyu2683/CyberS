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


def generate_report(cve_id: str) -> dict:
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

    return {
        "cve_id": cve_id,
        "summary": summary,
        "impact": analysis,
        "recommendations": recommendation,
        "risk_rating": risk_rating,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }
