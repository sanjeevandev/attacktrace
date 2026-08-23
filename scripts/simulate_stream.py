import time
import httpx
import json
import os

API_URL = "http://attacktrace-engine:8000/api/v1/stream/trigger"
SCENARIO_PATH = "data/attack_scenario.json"


def main():
    print("[SIMULATOR] Starting log stream simulator...")
    
    # Check alternate workspace location inside Docker
    target_path = SCENARIO_PATH
    if not os.path.exists(target_path):
        target_path = "/app/data/attack_scenario.json"
        
    if not os.path.exists(target_path):
        print(f"[SIMULATOR] Error: scenario path '{target_path}' not found!")
        return

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except Exception as e:
        print(f"[SIMULATOR] Error reading scenario logs: {e}")
        return

    print(f"[SIMULATOR] Loaded {len(logs)} log events. Commencing simulation stream...")
    
    # Loop infinitely to run simulation cycles
    while True:
        for log in logs:
            try:
                print(f"[SIMULATOR] Emitting event: {log.get('event_type')} from {log.get('source_ip')}")
                response = httpx.post(API_URL, json=[log], timeout=5.0)
                if response.status_code == 200:
                    print(f"[SIMULATOR] Server acknowledged: {response.json()}")
                else:
                    print(f"[SIMULATOR] Server error: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"[SIMULATOR] Failed to emit event: {e}")
            
            time.sleep(2.0)
            
        print("[SIMULATOR] Finished emitting attack scenario cycle. Restarting cycle...")
        time.sleep(5.0)


if __name__ == "__main__":
    main()
