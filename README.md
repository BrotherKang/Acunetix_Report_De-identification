# Acunetix Report De-identification 工具使用說明

## 功能概述

auto_clean_acunetix.py 是將 acunetix 產生出來的弱掃報告進行去識別化的小工具。

## 特色

- ✅ **多檔案處理**：若專案中有多的目標，可依序排列，並於最後列出對照表以供參考
- ✅ **歷史比對**：如果發現有相同的 URL 被去識別化則會沿用同樣的編號，確保專案內的一致性
- ✅ **單次執行，批次處理**：直接把腳本丟在充滿報告的資料夾執行，它會一次搞定所有檔案

## 系統需求

### 作業系統
- Linux (推薦 Ubuntu/Debian)
- macOS
- Windows

### Python 版本
- Python 3.6 或更高版本

## 安裝步驟

### 1. 安裝系統套件

- 基本上，都是使用內建的套件，無須再額外安裝套件

## 使用方法

1. 將弱掃報告與 auto_clean_acunetix.py 放在相同資料夾。
2. `python auto_clean_acunetix.py`
3. 它會自動跑完資料夾內所有報告

### 執行範例

以公開漏洞網站為例：

```bash
[-] 正在處理檔案: 20260128_Report_ASP.html
    [1/3] 偵測目標 URL...
    [+] 發現新目標: testasp.vulnweb.com => 分配代號: target_system_01
    [2/3] 去密化 HTML 內容...
    [3/3] 去密化加密數據...
    [O] 成功儲存為: cleaned_20260128_Report_ASP.html

[-] 正在處理檔案: 20260128_Report_PHP.html
    [1/3] 偵測目標 URL...
    [+] 發現新目標: testphp.vulnweb.com => 分配代號: target_system_02
    [2/3] 去密化 HTML 內容...
    [3/3] 去密化加密數據...
    [O] 成功儲存為: cleaned_20260128_Report_PHP.html

==================================================
去密化作業完成。以下是目標替換對照表：
==================================================
原始目標 (Original)                      | 替換代號 (Sanitized)
---------------------------------------------------------------
testasp.vulnweb.com                      | target_system_01    
testphp.vulnweb.com                      | target_system_02    
==================================================
```
