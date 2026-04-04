# 目標任務：CVE 自動分析 & 修復建議系統

## 背景

針對 AI x 資安工程師職位設計的 side project，展示 AI 技術應用於資安領域的能力。

## 目標

建立一個系統，輸入 CVE ID 後自動：
1. 爬取漏洞相關資訊
2. 用 LLM 分析影響範圍與攻擊向量
3. 生成對應的修復建議

## 功能規格

### 核心功能
- **CVE 資料擷取** — 串接 NVD API、OSV.dev、GitHub Advisory Database
- **LLM 漏洞分析** — 解讀漏洞影響範圍、攻擊條件、嚴重性
- **修復建議生成** — 針對不同語言/框架給出具體 patch 方向
- **影響評估** — 結合 CVSS 分數與實際攻擊情境給出風險評級

### 輸入 / 輸出
- **輸入**：CVE ID（例：CVE-2024-12345）
- **輸出**：結構化報告，包含摘要、影響範圍、修復建議、風險評級

## 技術選擇

| 元件 | 技術 |
|------|------|
| 語言 | Python |
| LLM | Anthropic Claude API |
| LLM Framework | LangChain / 直接用 SDK |
| 資料來源 | NVD API、OSV.dev、GitHub Advisory |
| 測試 | pytest |

## 對應 JD 能力

- AI 模型開發 → LLM prompt engineering、RAG
- 漏洞揭露後快速應對 → CVE 自動分析流程
- 修復建議生成 → structured output 設計
- 自動化分析工具 → pipeline 架構

## 待討論

- [ ] 專案工作流（寫 code → 測試 → commit → push）
- [ ] Repo 結構
- [ ] 開發 milestone 拆分
