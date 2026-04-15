import os
import glob
import requests
import json
import urllib3

# SSL xəbərdarlıqlarını (self-signed sertifikatlar üçün) söndürürük
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fayl yollarını təyin edirik (Sənin GitHub strukturuna uyğun)
QRADAR_PATH = "qradar/aql_queries/*.json"
SPLUNK_PATH = "splunk/security/*.spl"

def sync_qradar():
    print("--- 🔵 QRadar API Sync Başladı ---")
    host = os.environ.get('QRADAR_URL')
    token = os.environ.get('QRADAR_TOKEN')

    if not host or not token:
        print(f"❌ Xəta: QRadar məlumatları çatışmır! Host: {host}")
        return

    files = glob.glob(QRADAR_PATH)
    if not files:
        print("ℹ️ QRadar üçün JSON faylı tapılmadı.")
        return

    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                rule_data = json.load(f)
            
            rule_name = os.path.basename(file_path).split('.')[0]
            url = f"https://{host}/api/analytics/rules"
            headers = {
                "SEC": token, 
                "Content-Type": "application/json",
                "Version": "17.0"
            }
            
            response = requests.post(url, headers=headers, json=rule_data, verify=False)
            print(f"Rule: {rule_name} | Status: {response.status_code}")
        except Exception as e:
            print(f"❌ {file_path} işlənərkən xəta: {e}")

def sync_splunk():
    print("\n--- 🟢 Splunk API Sync Başladı ---")
    host = os.environ.get('SPLUNK_URL')
    token = os.environ.get('SPLUNK_TOKEN')

    if not host or not token:
        print(f"❌ Xəta: Splunk məlumatları çatışmır! Host: {host}")
        return

    files = glob.glob(SPLUNK_PATH)
    if not files:
        print("ℹ️ Splunk üçün .spl faylı tapılmadı.")
        return

    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                query = f.read()
            
            rule_name = os.path.basename(file_path).split('.')[0]
            # Splunk Management Port adətən 8089 olur
            url = f"https://{host}:8089/servicesNS/admin/search/saved/searches"
            headers = {"Authorization": f"Bearer {token}"}
            
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
            
            # Əgər rule artıq varsa (409 Conflict), onu update edirik
            if response.status_code == 409:
                update_url = f"{url}/{rule_name}"
                response = requests.post(update_url, headers=headers, data=data, verify=False)
                print(f"Alert: {rule_name} | Status: Updated (409 -> 200)")
            else:
                print(f"Alert: {rule_name} | Status: {response.status_code}")
        except Exception as e:
            print(f"❌ {file_path} işlənərkən xəta: {e}")

if __name__ == "__main__":
    sync_qradar()
    sync_splunk()
