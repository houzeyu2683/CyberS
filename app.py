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
    inp = gr.Textbox(label="CVE ID", placeholder="CVE-2021-44228")
    btn = gr.Button("分析")
    out = gr.JSON()
    btn.click(fn=analyze, inputs=inp, outputs=out)

if __name__ == "__main__":
    demo.launch()
