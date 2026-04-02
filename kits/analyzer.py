"""
kits/analyzer.py — LLM 漏洞分析

analyze_cve(cve_data: dict) -> dict
使用 Google Generative AI 分析 CVE 的影響範圍、攻擊條件、嚴重性等。
"""

import json
import sys
import yaml
import google.generativeai  # noqa: ensure registered in sys.modules

with open("key.yaml") as f:
    _keys = yaml.safe_load(f)

sys.modules["google.generativeai"].configure(api_key=_keys["GOOGLE_API_KEY"])

REQUIRED_INPUT_KEYS = {"description", "cvss_score"}

SYSTEM_PROMPT = """\
你是一位資安漏洞分析專家。請根據提供的 CVE 資訊，以 JSON 格式回覆以下欄位：
- impact_summary: 漏洞影響摘要（字串）
- attack_vector: 攻擊向量，只能是 "Network"、"Local"、"Physical" 其中之一
- attack_conditions: 攻擊條件描述（字串）
- severity_label: 嚴重性標籤，只能是 "Critical"、"High"、"Medium"、"Low" 其中之一
- exploitability: 可利用性描述（字串）
- affected_components: 受影響的元件列表（字串陣列）

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


def analyze_cve(cve_data: dict) -> dict:
    """
    分析 CVE 資料，回傳包含影響摘要、攻擊向量等的 dict。
    """
    if cve_data is None:
        raise TypeError("cve_data must be a dict, got None")
    if not isinstance(cve_data, dict):
        raise TypeError(f"cve_data must be a dict, got {type(cve_data).__name__}")
    for key in REQUIRED_INPUT_KEYS:
        if key not in cve_data:
            raise KeyError(f"cve_data missing required key: {key!r}")

    prompt = f"""\
CVE ID: {cve_data.get('cve_id', 'unknown')}
描述: {cve_data['description']}
CVSS Score: {cve_data['cvss_score']}
CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
發布日期: {cve_data.get('published', 'N/A')}
受影響套件: {json.dumps(cve_data.get('affected_packages', []), ensure_ascii=False)}
參考連結: {json.dumps(cve_data.get('references', []), ensure_ascii=False)}

請分析此漏洞並以指定 JSON 格式回覆。
"""
    result = call_llm(prompt, SYSTEM_PROMPT)
    if result is None:
        raise ValueError("call_llm returned None")
    return result
