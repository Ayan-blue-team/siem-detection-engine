import os
import requests
import json

# QRadar məlumatları GitHub Secrets-dən gəlir
QRADAR_URL = os.getenv('QRADAR_URL') # Məs: https://1.2.3.4
QRADAR_TOKEN = os.getenv('QRADAR_TOKEN')

# Qovluq yollarını dinamik təyin edirik (Xəta almamaları üçün)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE_DIR, 'rules')

headers = {
    'SEC': QRADAR_TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

def sync_to_qradar():
    if not os.path.exists(RULES_DIR):
        print(f"Xəta: {RULES_DIR} qovluğu tapılmadı!")
        return

    for filename in os.listdir(RULES_DIR):
        if filename.endswith('.json'):
            file_path = os.path.join(RULES_DIR, filename)
            with open(file_path, 'r') as f:
                try:
                    rule_data = json.load(f)
                    print(f"Yüklənir: {filename}...")
                    
                    # QRadar API-yə Rule göndərilməsi
                    # Qeyd: Mövcud qaydanı update etmək üçün PUT, yenisini yaratmaq üçün POST
                    response = requests.post(
                        f"{QRADAR_URL}/api/analytics/rules", 
                        headers=headers, 
                        json=rule_data, 
                        verify=False
                    )
                    
                    if response.status_code in [200, 201]:
                        print(f"Uğurlu: {filename} SIEM-də aktivdir.")
                    else:
                        print(f"Xəta {filename}: {response.status_code} - {response.text}")
                except Exception as e:
                    print(f"Fayl oxunarkən xəta: {filename} - {str(e)}")

if __name__ == "__main__":
    # SSL xətalarını görməzdən gəlmək üçün (Self-signed sertifikatlar üçün)
    requests.packages.urllib3.disable_warnings()
    sync_to_qradar()
