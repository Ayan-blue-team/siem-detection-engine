import os
import glob
import requests
import urllib3

# SSL xəbərdarlıqlarını söndürürük
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Yalnız Splunk fayl yolu
SPLUNK_PATH = "splunk/security/*.spl"

def sync_splunk():
    print("\n--- 🟢 Splunk API Sync Başladı ---")
    host = os.environ.get('SPLUNK_URL')
    token = os.environ.get('SPLUNK_TOKEN')

    if not host or not token:
        print(f"❌ Xəta: Splunk məlumatları çatışmır! Host və ya Token yoxdur.")
        return

    files = glob.glob(SPLUNK_PATH)
    if not files:
        print("ℹ️ Splunk üçün .spl faylı tapılmadı.")
        return

    headers = {"Authorization": f"Bearer {token}"}
    
    for file_path in files:
        try:
            with open(file_path, 'r') as f:
                query = f.read()
            
            rule_name = os.path.basename(file_path).split('.')[0]
            # Splunk Management Port (8089)
            url = f"https://{host}:8089/servicesNS/admin/search/saved/searches"
            
            data = {
                "name": rule_name,
                "search": query,
                "is_scheduled": 1,
                "cron_schedule": "*/5 * * * *",
                "alert_type": "number of events",
                "alert_comparator": "greater than",
                "alert_threshold": 0
            }
            
            # Qaydanı yaratmağa çalışırıq
            response = requests.post(url, headers=headers, data=data, verify=False)
            
            # Əgər qayda artıq varsa (409 Conflict), onu update edirik
            if response.status_code == 409:
                update_url = f"{url}/{rule_name}"
                response = requests.post(update_url, headers=headers, data=data, verify=False)
                if response.status_code == 200:
                    print(f"Alert: {rule_name} | Status: Updated (409 -> 200)")
                else:
                    print(f"Alert: {rule_name} | Xəta (Update): {response.status_code} - {response.text}")
            elif response.status_code == 201:
                print(f"Alert: {rule_name} | Status: Created (201)")
            else:
                print(f"Alert: {rule_name} | Status: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"❌ {file_path} işlənərkən xəta: {e}")

if __name__ == "__main__":
    sync_splunk()
