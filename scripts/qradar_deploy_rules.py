import requests
import json
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONFİQURASİYA ---
# Tokeni birbaşa bura yapışdır, amma mesajda HEÇ KİMƏ GÖSTƏRMƏ!
GITHUB_TOKEN = "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" 
GITHUB_REPO_API = "https://api.github.com/repos/Ayan-blue-team/siem-detection-engine/contents/qradar/rules"

QRADAR_IP = "18.212.3.25"
QRADAR_SEC_TOKEN = "12622cc0-bc6c-4e07-becb-884ccada0deb"

def upload_to_qradar(rule_content):
    q_url = f"https://{QRADAR_IP}/api/analytics/rules"
    headers = {
        "SEC": QRADAR_SEC_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    try:
        # XƏTA ANALİZİ: QRadar-dan gələn cavabı print edirik
        response = requests.post(q_url, headers=headers, data=rule_content, verify=False)
        return response.status_code in [200, 201], response.text
    except Exception as e:
        return False, str(e)

def process_github_to_qradar():
    gh_headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}", # Bearer istifadə etmək daha yaxşıdır
        "Accept": "application/vnd.github.v3+json"
    }

    print(f"[*] GitHub-a qoşulur...")
    gh_res = requests.get(GITHUB_REPO_API, headers=gh_headers)
    
    if gh_res.status_code != 200:
        print(f"[X] GitHub API xətası (Status: {gh_res.status_code}): {gh_res.text}")
        return

    rules = gh_res.json()
    
    for item in rules:
        if item['type'] == 'file' and item['name'].endswith('.json'):
            file_name = item['name']
            print(f"[*] İşlənir: {file_name}")
            
            file_res = requests.get(item['download_url'], headers=gh_headers)
            if file_res.status_code == 200:
                success, response = upload_to_qradar(file_res.text)
                if success:
                    print(f"  [✔] {file_name} uğurla yükləndi.")
                else:
                    print(f"  [!] {file_name} QRadar-a yüklənmədi. QRadar cavabı: {response}")
            else:
                print(f"  [!] GitHub-dan fayl oxuna bilmədi.")

if __name__ == "__main__":
    process_github_to_qradar()
