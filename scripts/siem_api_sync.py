import os
import requests
import json

# QRadar məlumatları (GitHub Secrets-dən götürüləcək)
QRADAR_CONSOLE = os.getenv('QRADAR_CONSOLE_IP')
API_TOKEN = os.getenv('QRADAR_API_TOKEN')

headers = {
    'SEC': API_TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

def deploy_rules():
    rules_path = 'rules/'
    for filename in os.listdir(rules_path):
        if filename.endswith('.json'):
            with open(os.path.join(rules_path, filename), 'r') as f:
                rule_data = json.load(f)
                
                # QRadar API-yə POST sorğusu
                url = f"https://{QRADAR_CONSOLE}/api/analytics/rules"
                response = requests.post(url, headers=headers, json=rule_data, verify=False)
                
                if response.status_code == 201:
                    print(f"Uğurlu: {filename} SIEM-ə əlavə edildi.")
                else:
                    print(f"Xəta: {filename} yüklənmədi. Status: {response.status_code}")

if __name__ == "__main__":
    deploy_rules()
