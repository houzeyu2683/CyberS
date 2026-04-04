import re
from dotenv import load_dotenv
load_dotenv()
import gradio as gr
from kits.reporter import generate_report, report_to_markdown

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$")


def analyze(cve_id: str, check_poc: bool = False, check_kev: bool = False, check_epss: bool = False):
    if not cve_id or not isinstance(cve_id, str) or not cve_id.strip():
        return {"error": "Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN"}
    if not CVE_PATTERN.match(cve_id.strip()):
        return {"error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNNN"}
    try:
        return generate_report(cve_id.strip(), check_poc=check_poc, check_kev=check_kev, check_epss=check_epss)
    except Exception as e:
        return {"error": str(e)}


def to_markdown(report_json):
    if not report_json or "error" in report_json:
        return "尚無報告，請先執行分析。", gr.update(visible=False)
    md_text = report_to_markdown(report_json)
    path = "/tmp/cve_report.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(md_text)
    return md_text, gr.update(value=path, visible=True)


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

**威脅情報選項**
- 偵測 PoC：透過 GitHub Search API 查詢是否有公開 PoC 倉庫
- 偵測 In the Wild：查詢 CISA KEV 資料庫確認是否已知在野利用
- 偵測 EPSS：透過 FIRST API 查詢未來 30 天被利用的機率分數與百分位排名
""")
    inp = gr.Textbox(label="CVE ID", placeholder="CVE-2021-44228")
    poc_cb = gr.Checkbox(label="偵測 PoC（GitHub Search API）", value=False)
    kev_cb = gr.Checkbox(label="偵測 In the Wild（CISA KEV）", value=False)
    epss_cb = gr.Checkbox(label="偵測 EPSS（FIRST API）", value=False)
    btn = gr.Button("分析")
    out = gr.JSON()
    btn.click(fn=analyze, inputs=[inp, poc_cb, kev_cb, epss_cb], outputs=out)
    md_btn = gr.Button("產生 Markdown 報告")
    md_out = gr.Markdown()
    dl_btn = gr.DownloadButton(label="下載 .md 報告", visible=False)
    md_btn.click(fn=to_markdown, inputs=[out], outputs=[md_out, dl_btn])

if __name__ == "__main__":
    demo.launch()
