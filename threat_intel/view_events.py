import json
import sys
import io
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import EVENT_LOG_FILE

def view_logs():
    if not EVENT_LOG_FILE.exists():
        print("[!] Chưa có file logs/events.jsonl nào.")
        return

    print("=" * 95)
    print(f"📊 [SOC THREAT INTEL VIEWER] TỔNG HỢP SỰ KIỆN TỪ: {EVENT_LOG_FILE}")
    print("=" * 95)
    print(f"{'TIME':<12} | {'IP':<15} | {'HANDLER':<18} | {'LATENCY':<8} | {'MITRE':<8} | {'COMMAND'}")
    print("-" * 95)

    with open(EVENT_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            t_short = item["timestamp"][11:19]
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
