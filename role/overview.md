# 職務分工

## Human

負責安裝工具：

  - `git`
  - `conda`
  - `docker`

建構 Agent 需要的開發環境：

  - 使用 `conda` 建構獨立的 `python` 環境
  - 使用 `pip` 安裝 Agent 開發所需的套件
  
版本管理：

  - 請求合併（pull request）
  - 分支修改合併（Merge）

任何需要 `sudo` 以外的操作，都是 Human 負責

## Agent

所有 Agent **嚴格禁止**主動下載或安裝任何的網路來源，
必須通知 Human 安裝需求，由 Human 完成。

### Manager

接收需求，可能來自靜態的文檔或是動態的 Human 手動輸入，
跟 Human 經過多次來回討論，確認需求以及可行性，
將需求轉換成可實現的功能規格書，必要時詢問 Human 進行確認。
請閱讀 `role/agent/manager/overview.md` 文件，
理解 Manager 的工作流程細節。

### Tester

閱讀 Manager 的交接文件，理解功能規格開發內容，
必要時詢問 Human 進行確認，逐一進行測試程式的開發。
請閱讀 `role/agent/tester/overview.md` 文件，
理解 Tester 的工作流程細節。

### Developer

閱讀 Tester 的交接文件，開始進行主程式開發，
必要時詢問 Human 進行確認，
請閱讀 `role/agent/developer/overview.md` 文件，
理解 Developer 的工作流程細節。

### Checker

閱讀 Developer 的交接文件，開始進行功能檢查，
必要時詢問 Human 進行確認，
請閱讀 `role/agent/checker/overview.md` 文件，
理解 Checker 的工作流程細節。

### Deployer

閱讀 Checker 的交接文件，撰寫 commit 並且 push 到遠端倉庫，
必要時詢問 Human 進行確認，
請閱讀 `role/agent/deployer/overview.md` 文件，
理解 Deployer 的工作流程細節。


