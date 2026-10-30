import json
import sys
import io
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import EVENT_LOG_FILE

def load_events(file_path: Path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    if not content:
        return []
    
    # Hỗ trợ đọc cả JSON array đã format đẹp [ ... ] lẫn JSON Lines chuẩn
    if content.startswith("["):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

    events = []
    decoder = json.JSONDecoder()
    idx = 0
    length = len(content)
    while idx < length:
        while idx < length and content[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            obj, end_idx = decoder.raw_decode(content, idx)
            events.append(obj)
            idx = end_idx
        except json.JSONDecodeError:
            next_nl = content.find("\n", idx)
            if next_nl == -1:
                break
            idx = next_nl + 1
    return events

def view_logs():
    if not EVENT_LOG_FILE.exists():
        print("[!] Chưa có file logs/events.jsonl nào.")
        return

    print("=" * 95)
    print(f"📊 [SOC THREAT INTEL VIEWER] TỔNG HỢP SỰ KIỆN TỪ: {EVENT_LOG_FILE}")
    print("=" * 95)
    print(f"{'TIME':<12} | {'IP':<15} | {'HANDLER':<18} | {'LATENCY':<8} | {'MITRE':<8} | {'COMMAND'}")
    print("-" * 95)

    events = load_events(EVENT_LOG_FILE)
    for item in events:
        t_short = item.get("timestamp", "")[11:19]
        ip = item.get("source_ip", "")
        handler = item.get("handler_type", "")
        lat = f"{item.get('latency_ms', 0):.2f}ms"
        mitre_list = item.get("mitre_techniques", [])
        mitre_id = mitre_list[0]["technique_id"] if mitre_list else "-"
        cmd = item.get("command", "")
        
        print(f"{t_short:<12} | {ip:<15} | {handler:<18} | {lat:<8} | {mitre_id:<8} | {cmd}")
    print("=" * 95)

if __name__ == "__main__":
    view_logs()
