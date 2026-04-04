"""
kits/recommender.py — 修復建議生成

generate_recommendation(cve_data: dict, analysis: dict) -> dict
使用 Google Generative AI 根據 CVE 資料與分析結果生成修復建議。
"""

import json
import os
import sys
import google.generativeai  # noqa: ensure registered in sys.modules

sys.modules["google.generativeai"].configure(api_key=os.environ["GOOGLE_API_KEY"])

SYSTEM_PROMPT = """\
你是一位資安修復建議專家。請根據提供的 CVE 資訊與分析結果，以 JSON 格式回覆以下欄位：
- patch_actions: 修補行動列表（字串陣列，至少一項）
- workarounds: 暫時緩解方案列表（字串陣列，可為空）
- language_specific: 各程式語言的具體建議（dict，可為空 dict）
- priority: 優先級，只能是 "Immediate"、"Planned"、"Monitor" 其中之一

只回覆 JSON，不要有其他說明文字。
"""


def call_llm(prompt: str, system_prompt: str) -> dict:
    """呼叫 Google Generative AI，回傳解析後的 dict。"""
    import re
    genai = sys.modules["google.generativeai"]
    model = genai.GenerativeModel(
        model_name="gemini-2.5-flash",
        system_instruction=system_prompt,
    )
    response = model.generate_content(prompt)
    text = response.text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def generate_recommendation(cve_data: dict, analysis: dict) -> dict:
    """
    根據 CVE 資料與分析結果生成修復建議。
    """
    if cve_data is None or analysis is None:
        raise TypeError("cve_data and analysis must be dicts, not None")
    if not isinstance(cve_data, dict):
        raise TypeError(f"cve_data must be a dict, got {type(cve_data).__name__}")
    if not isinstance(analysis, dict):
        raise TypeError(f"analysis must be a dict, got {type(analysis).__name__}")
    if "severity_label" not in analysis:
        raise KeyError("analysis missing required key: 'severity_label'")

    prompt = f"""\
CVE ID: {cve_data.get('cve_id', 'unknown')}
描述: {cve_data.get('description', '')}
CVSS Score: {cve_data.get('cvss_score', 'N/A')}
受影響套件: {json.dumps(cve_data.get('affected_packages', []), ensure_ascii=False)}

分析結果：
- 影響摘要: {analysis.get('impact_summary', '')}
- 攻擊向量: {analysis.get('attack_vector', '')}
- 嚴重性: {analysis['severity_label']}
- 可利用性: {analysis.get('exploitability', '')}
- 受影響元件: {json.dumps(analysis.get('affected_components', []), ensure_ascii=False)}

請生成修復建議並以指定 JSON 格式回覆。
"""
    result = call_llm(prompt, SYSTEM_PROMPT)
    if result is None:
        raise ValueError("call_llm returned None")
    return result
