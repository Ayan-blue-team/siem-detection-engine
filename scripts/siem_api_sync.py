import os
import glob
import requests
import json

# --- Fayl Yolları ---
QRADAR_PATH = "qradar/aql_queries/*.json"
SPLUNK_PATH = "splunk/security/*.spl"

def sync_qradar():
    print("--- 🔵 QRadar API Sync ---")
    files = glob.glob(QRADAR_PATH)
    for file_path in files:
        with open(file_path, 'r') as f:
            rule_data = json.load(f)
            # Fayl adını rule adı kimi istifadə edirik
            rule_name = os.path.basename(file_path).split('.')[0]
            
            # API URL və Header (Host və Token GitHub Secret-dən gəlir)
            url = f"https://{os.environ['QRADAR_URL']}/api/analytics/rules"
            headers = {"SEC": os.environ['QRADAR_TOKEN'], "Content-Type": "application/json"}
            
            # QRadar API-yə göndərilmə məntiqi
            response = requests.post(url, headers=headers, json=rule_data, verify=False)
            print(f"Rule: {rule_name} | Status: {response.status_code}")

def sync_splunk():
    print("\n--- 🟢 Splunk API Sync ---")
    files = glob.glob(SPLUNK_PATH)
    for file_path in files:
        with open(file_path, 'r') as f:
            query = f.read()
            rule_name = os.path.basename(file_path).split('.')[0]
            
            url = f"https://{os.environ['SPLUNK_URL']}:8089/servicesNS/admin/search/saved/searches"
            headers = {"Authorization": f"Bearer {os.environ['SPLUNK_TOKEN']}"}
            
            # Splunk axtarış parametrləri
            data = {
                "name": rule_name,
                "search": query,
                "is_scheduled": 1,
                "cron_schedule": "*/5 * * * *",
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": 0
            }
            
            response = requests.post(url, headers=headers, data=data, verify=False)
            print(f"Alert: {rule_name} | Status: {response.status_code}")

if __name__ == "__main__":
    sync_qradar()
    sync_splunk()
