import base64
import gzip
import json
import re
import os
import sys
import glob

class AcunetixSanitizer:
    def __init__(self):
        # 用來儲存 真實URL -> 去密化代號 的對照表
        self.target_map = {} 
        self.counter = 1
        self.base_name = "target_system"

    def get_placeholder(self, real_host):
        """
        取得或建立該 Host 的代號
        """
        # 統一轉小寫以避免大小寫視為不同目標
        key = real_host.lower()
        
        if key not in self.target_map:
            # 如果是新目標，分配新 ID
            placeholder = f"{self.base_name}_{self.counter:02d}"
            self.target_map[key] = {
                "original": real_host,
                "placeholder": placeholder
            }
            self.counter += 1
            print(f"    [+] 發現新目標: {real_host} => 分配代號: {placeholder}")
        
        return self.target_map[key]["placeholder"]

    def detect_hosts_in_block(self, scan_data_block):
        """
        預先掃描數據塊，找出這份報告裡面包含的所有目標 Host
        """
        lines = scan_data_block.strip().split('\n')
        check_limit = min(len(lines), 50) # 檢查前50行
        
        found_hosts = set()

        for i in range(check_limit):
            line = lines[i].strip()
            if not line: continue
            
            try:
                decoded_bytes = base64.b64decode(line)
                # 處理 Gzip
                if decoded_bytes[:2] == b'\x1f\x8b':
                    try:
                        json_str = gzip.decompress(decoded_bytes).decode('utf-8', errors='ignore')
                    except:
                        continue
                else:
                    json_str = decoded_bytes.decode('utf-8', errors='ignore')

                # 解析 JSON 找 host
                try:
                    data = json.loads(json_str)
                    if isinstance(data, dict):
                        # 抓取 host 欄位
                        if 'host' in data and data['host']:
                            found_hosts.add(data['host'])
                        
                        # 抓取 start_url 欄位並提取 domain
                        if 'start_url' in data and data['start_url']:
                            match = re.search(r'://([^/:]+)', data['start_url'])
                            if match:
                                found_hosts.add(match.group(1))
                except json.JSONDecodeError:
                    pass
            except Exception:
                continue
        
        # 將找到的 Host 註冊進對照表
        for host in found_hosts:
            self.get_placeholder(host)

    def sanitize_text(self, text):
        """
        將文字中的所有已知 Target 替換為對應代號
        """
        if not self.target_map:
            return text

        is_bytes = False
        if isinstance(text, bytes):
            try:
                text = text.decode('utf-8')
                is_bytes = True
            except:
                return text

        # 依序替換所有已註冊的目標
        # 注意：這裡不只替換當前檔案發現的，而是替換所有已知的，避免漏網之魚
        for key, info in self.target_map.items():
            original = info['original']
            placeholder = info['placeholder']
            
            # 使用 re.escape 處理網址中的特殊字元，並忽略大小寫
            pattern = re.compile(re.escape(original), re.IGNORECASE)
            text = pattern.sub(placeholder, text)

        if is_bytes:
            return text.encode('utf-8')
        return text

    def process_scan_data_line(self, line):
        """
        處理單行加密數據
        """
        line = line.strip()
        if not line: return line

        try:
            decoded_data = base64.b64decode(line)
            is_gzipped = False
            
            if decoded_data[:2] == b'\x1f\x8b':
                try:
                    working_data = gzip.decompress(decoded_data)
                    is_gzipped = True
                except:
                    working_data = decoded_data
            else:
                working_data = decoded_data

            # 執行替換
            sanitized_data = self.sanitize_text(working_data)

            # 還原壓縮與編碼
            if is_gzipped:
                sanitized_data = gzip.compress(sanitized_data, mtime=0)

            return base64.b64encode(sanitized_data).decode('ascii')

        except Exception:
            return line

    def process_file(self, file_path):
        print(f"[-] 正在處理檔案: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[X] 讀取失敗: {e}")
            return

        # 定位 scanData 區塊
        start_marker = '<script id="scanData" type="application/octet-stream">'
        end_marker = '</script>'
        
        start_pos = content.find(start_marker)
        if start_pos == -1:
            print("[!] 找不到 scanData 區塊，跳過。")
            return
        
        end_pos = content.find(end_marker, start_pos)
        if end_pos == -1:
            print("[!] 報告結構不完整。")
            return

        # 提取數據塊
        scan_data_block = content[start_pos + len(start_marker):end_pos]
        
        # 1. 偵測階段：找出這份報告裡面的目標，並註冊 ID
        print("    [1/3] 偵測目標 URL...")
        self.detect_hosts_in_block(scan_data_block)

        # 2. 處理 HTML 表層 (Header/Footer)
        print("    [2/3] 去密化 HTML 內容...")
        header_html = content[:start_pos + len(start_marker)]
        footer_html = content[end_pos:]
        
        header_html = self.sanitize_text(header_html)
        footer_html = self.sanitize_text(footer_html)

        # 3. 處理加密數據層
        print("    [3/3] 去密化加密數據...")
        lines = scan_data_block.strip().split('\n')
        new_lines = []
        for line in lines:
            new_lines.append(self.process_scan_data_line(line))
        
        new_scan_data_block = '\n'.join(new_lines)

        # 存檔
        new_content = header_html + '\n' + new_scan_data_block + '\n' + footer_html
        new_filename = "cleaned_" + os.path.basename(file_path)
        
        try:
            with open(new_filename, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"    [O] 成功儲存為: {new_filename}\n")
        except Exception as e:
            print(f"    [X] 寫入失敗: {e}\n")

    def print_summary(self):
        print("="*50)
        print("去密化作業完成。以下是目標替換對照表：")
        print("="*50)
        print(f"{'原始目標 (Original)':<40} | {'替換代號 (Sanitized)':<20}")
        print("-" * 63)
        for key, info in self.target_map.items():
            print(f"{info['original']:<40} | {info['placeholder']:<20}")
        print("="*50)

if __name__ == "__main__":
    print("=== Acunetix 多目標自動編號去密化工具 ===\n")
    
    sanitizer = AcunetixSanitizer()

    # 取得檔案列表
    files = []
    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        all_htmls = glob.glob("*.html")
        files = [f for f in all_htmls if not f.startswith("cleaned_")]

    if not files:
        print("未找到 HTML 檔案。請將腳本放在報告資料夾中執行。")
        input("按 Enter 鍵離開...")
    else:
        print(f"找到 {len(files)} 個檔案，開始執行...\n")
        
        # 依序處理每個檔案
        for file in files:
            if os.path.isfile(file):
                sanitizer.process_file(file)
        
        # 顯示對照表
        sanitizer.print_summary()
