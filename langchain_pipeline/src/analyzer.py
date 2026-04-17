import os
import json
import re
import requests
import collections
import subprocess
from datetime import datetime
from pathlib import Path
from openai import OpenAI

# === Cấu hình ===
LOG_DIR = Path("/home/imsupershy/monitoring-project/langchain_pipeline/logs")
LOG_FILE_PATH = LOG_DIR / "collector.log"
AI_OUTPUT_FILE = LOG_DIR / "ai_insights.json"
ANALYZER_LOG_FILE = LOG_DIR / "analyzer_output.log"
BLOCKED_IPS_FILE = LOG_DIR / "blocked_ips.json" # File lưu trữ danh sách chặn

LAST_N_LINES = 200

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
model_name = "nvidia/nemotron-3-super-120b-a12b:free"

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENAI_API_KEY")
)

# --- NEW: HÀM QUẢN LÝ BLACKLIST ---
def load_blocked_ips():
    """Tải danh sách IP đã bị chặn từ file."""
    if not BLOCKED_IPS_FILE.exists():
        return {}
    try:
        return json.loads(BLOCKED_IPS_FILE.read_text())
    except:
        return {}

def save_blocked_ip(ip, reason="Manual Block"):
    """Lưu IP vào danh sách chặn."""
    blocked_data = load_blocked_ips()
    blocked_data[ip] = {
        "blocked_at": datetime.utcnow().isoformat(),
        "reason": reason
    }
    BLOCKED_IPS_FILE.write_text(json.dumps(blocked_data, indent=2))
    print(f"[ACTION] IP {ip} đã được thêm vào Blacklist.")

# --- GIỮ NGUYÊN HÀM INTEL ---
def get_ip_intel(ip_address):
    if not ip_address or ip_address.startswith(("127.", "192.168.", "10.")):
        return None
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "ip": ip_address,
                "abuse_score": data.get("abuseConfidenceScore"),
                "country": data.get("countryCode"),
                "isp": data.get("isp")
            }
    except Exception as e:
        print(f"[ERROR IP Intel]: {e}")
    return None

def read_last_n_lines(file_path, n=200):
    if not file_path.exists(): return ""
    try:
        with open(file_path, "rb") as f:
            f.seek(0, 2)
            pointer = f.tell()
            buffer = bytearray()
            lines_found = 0
            while pointer >= 0 and lines_found < n:
                f.seek(pointer)
                byte = f.read(1)
                if byte == b"\n": lines_found += 1
                buffer.extend(byte)
                pointer -= 1
            buffer.reverse()
            return buffer.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[ERROR đọc log]: {str(e)}"

def analyze_logs():
    log_content = read_last_n_lines(LOG_FILE_PATH, LAST_N_LINES)
    if not log_content:
        return {"severity": "INFO", "behavior_summary": "Không có log mới", "recommendation": "N/A"}

    # Tải danh sách đã chặn
    blocked_ips = load_blocked_ips()

    ip_groups = collections.defaultdict(list)
    ip_pattern = r'"source_ip":\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"'

    lines = log_content.strip().split('\n')
    for line in lines:
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group(1)
            # --- CẢI TIẾN: Bỏ qua IP đã nằm trong Blacklist ---
            if ip in blocked_ips:
                continue
            ip_groups[ip].append(line)

    if not ip_groups:
        return {"severity": "INFO", "behavior_summary": "Tất cả IP hiện tại đều nằm trong Blacklist hoặc không có IP mới.", "recommendation": "N/A"}

    behavior_context = ""
    intel_reports = []
    top_ips = sorted(ip_groups.items(), key=lambda x: len(x[1]), reverse=True)[:5]

    for ip, logs in top_ips:
        intel = get_ip_intel(ip)
        if intel:
            intel_reports.append(intel)
        recent_actions = logs[-5:]
        behavior_context += f"\n[IP: {ip}]\n"
        behavior_context += f"- Tần suất: {len(logs)} yêu cầu\n"
        behavior_context += f"- Chuỗi hành vi: " + " -> ".join([re.search(r'"request_url":\s*"([^"]+)"', l).group(1) if re.search(r'"request_url":\s*"([^"]+)"', l) else "unknown" for l in recent_actions]) + "\n"

    prompt = f"""
    Bạn là chuyên gia SOC Tier 3. Phân tích chuỗi hành vi sau:
    {behavior_context}
    Threat Intel: {json.dumps(intel_reports)}
    Trả về JSON:
    {{
      "severity": "CRITICAL/WARNING/INFO",
      "attack_category": "Tên loại tấn công",
      "mitre_technique": "Mã MITRE",
      "behavior_summary": "Tóm tắt hành vi",
      "recommendation": "Hướng xử lý"
    }}
    """

    try:
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "Phân tích bảo mật chuyên sâu."},
                {"role": "user", "content": prompt},
            ],
        )
        result = json.loads(completion.choices[0].message.content)
        result["ip_intel"] = intel_reports
    except Exception as e:
        result = {"severity": "unknown", "behavior_summary": f"Lỗi: {e}", "recommendation": "Kiểm tra hệ thống"}

    return result

if __name__ == "__main__":
    insight = analyze_logs()
    severity = insight.get("severity")

    if severity in ["WARNING", "CRITICAL", "INFO"]:
        # Lấy thông tin IP nguy hiểm nhất để xử lý (nếu có)
        ip_intel_list = insight.get("ip_intel", [])
        first_intel = ip_intel_list[0] if ip_intel_list else {}
        
        # --- MÔ PHỎNG PHẢN ỨNG TỰ ĐỘNG ---
        # Nếu severity là CRITICAL và điểm độc hại > 80, ta tự động đưa vào Blacklist
        target_ip = first_intel.get("ip")
        '''if severity == "CRITICAL" and first_intel.get("abuse_score", 0) > 80 and target_ip:
            save_blocked_ip(target_ip, reason=insight.get("attack_category"))'''
        # --- MÔ PHỎNG PHẢN ỨNG TỰ ĐỘNG (TEST MODE) ---
        if severity in ["CRITICAL", "WARNING"] and target_ip:
            print(f"[PROCESS] Đang gửi yêu cầu phê duyệt chặn IP {target_ip} tới Telegram...")
            
            # Gọi hàm gửi tin nhắn từ telegram_handler (Chạy độc lập)
            cmd = [
                "python3", "-c",
                f"import asyncio; from telegram_handler import send_interactive_alert; "
                f"asyncio.run(send_interactive_alert('{target_ip}', '{severity}', "
                f"'{insight.get('attack_category')}', '{insight.get('behavior_summary')[:50]}...'))"
            ]
            subprocess.Popen(cmd, cwd=str(LOG_DIR.parent / "src"))

        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "AI_ANALYZER",
            "ai_model": model_name,
            "severity": severity,
            "attack_category": insight.get("attack_category", "N/A"),
            "mitre_technique": insight.get("mitre_technique", "N/A"),
            "summary": insight.get("behavior_summary"),
            "recommendation": insight.get("recommendation"),
            "target_ip": target_ip or "",
            "country_code": first_intel.get("country", ""),
            "abuse_score": first_intel.get("abuse_score", 0),
            "isp": first_intel.get("isp", ""),
            "details": ip_intel_list
        }

        AI_OUTPUT_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        with open(ANALYZER_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")
        print(f"[ALERT LOGGED] Severity: {severity} | IP: {target_ip}")