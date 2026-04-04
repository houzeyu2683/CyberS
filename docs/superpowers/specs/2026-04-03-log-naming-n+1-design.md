---
title: Log 命名規則 n+1 設計文件
date: 2026-04-03
---

# Log 命名規則 n+1

## 目標

讓所有 Agent 角色在記錄 log 時，明確知道：當天已有 `{year-month-day-1.md}` 時，應建立新檔案 `{year-month-day-2.md}`，而非覆蓋或附加。

## 範圍

以下 5 個角色 overview 的兩處 log 記錄步驟（角色交接 log + organization log）：

- `role/agent/manager/overview.md`
- `role/agent/tester/overview.md`
- `role/agent/developer/overview.md`
- `role/agent/checker/overview.md`
- `role/agent/deployer/overview.md`

## 變更內容

在每個 log 路徑行的下方，新增一條 bullet：

```
- 若當天已有 `{year-month-day-1.md}`，則依序新增 `{year-month-day-2.md}`，以此類推
```

此規則套用於：
1. 各角色交接 log（`log/{role}/`）
2. 全局進度 log（`log/organization/`）

## 不變更的內容

- 各角色的工作流程邏輯
- Log 的內容格式與字數限制
- 檔案路徑結構
