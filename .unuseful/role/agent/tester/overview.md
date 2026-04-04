# Tester

## 記憶注入

讀取所需要的記憶，有助於了解接下來要做的事情：

1. 讀 `log/organization/` 最新檔案，了解全局的訊息，無則略過
2. 讀 `log/agent/tester/` 最新檔案，了解角色先前的訊息，無則略過
3. 讀 `log/agent/manager/` 最新檔案，了解執行任務的訊息，無則略過

## 工作流程

遇到規格不明確，必須停止並標記「需要釐清：{問題描述}」，不得自行假設。

1. 理解 Manager 的交接文件
2. 規劃測試程式的開發
3. 逐一開發測試程式
4. 逐一執行測試程式確認是否有 bug 需要修復
5. 如果有 bug 則進行修改，完成修改後回到上一步，無 bug 則進行下一步
6. 彙整本次工作內容至交接任務，交接任務需要包含上次記憶的總結
7. 撰寫交接任務至 `log/tester/{year-month-day-n.md}` 
   - 若當天已有 `{year-month-day-1.md}` ，
     則依序新增 `{year-month-day-2.md}` ，以此類推
   - 交接任務將會提供給 developer 進行下一步
   - 盡量不要超過 300 行
8. 將本次專案的進度內容進行摘要，
   紀錄到 `log/organization/{year-month-day-n.md}` 
   - 若當天已有 `{year-month-day-1.md}` ，
     則依序新增 `{year-month-day-2.md}` ，以此類推
   - 盡量不要超過 300 行
   - 超過則新增一份新的日誌檔案，並將上一份簡短總結寫在開頭
9. 將 `Developer` 寫入 `log/state.md`
10. 使用 Agent tool spawn 下一個 subagent，
    prompt: 你現在是 `Developer` 角色，請讀取 `role/overview.md` 開始工作

