import re
import gradio as gr
from kits.reporter import generate_report

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$")


def analyze(cve_id: str):
    if not cve_id or not isinstance(cve_id, str) or not cve_id.strip():
        return {"error": "Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN"}
    if not CVE_PATTERN.match(cve_id.strip()):
        return {"error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNNN"}
    try:
        return generate_report(cve_id.strip())
    except Exception as e:
        return {"error": str(e)}


with gr.Blocks() as demo:
    gr.Markdown("""
## CVE 自動分析系統

**專案用途**
輸入 CVE ID，系統自動從 NVD、OSV.dev、GitHub Advisory 擷取漏洞資訊，
透過 AI 分析影響範圍與攻擊向量，並生成具體的修復建議。

**使用流程**
1. 在下方輸入框填入 CVE ID（例：CVE-2021-44228）
2. 點擊「分析」按鈕
3. 查看右側 JSON 報告，包含漏洞摘要、影響分析、修復建議與風險評級
""")
    inp = gr.Textbox(label="CVE ID", placeholder="CVE-2021-44228")
    btn = gr.Button("分析")
    out = gr.JSON()
    btn.click(fn=analyze, inputs=inp, outputs=out)

if __name__ == "__main__":
    demo.launch()
