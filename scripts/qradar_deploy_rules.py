import requests
import json
import urllib3
import os

# QRadar sertifikat xəbərdarlıqlarını gizlədirik
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONFİQURASİYA ---
# GitHub Tokenini bura yapışdır (Dırnaqlar içində)
GITHUB_TOKEN = "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".strip()

# GitHub API URL-i (Bunu öz repo məlumatlarına görə dəyiş)
# FORMAT: https://api.github.com/repos/İSTİFADƏÇİ/REPO/contents/QOVLUQ
GITHUB_REPO_API = "https://api.github.com/repos/Ayan-blue-team/siem-detection-engine/contents/qradar/rules"

# QRadar Console Məlumatları
QRADAR_IP = "18.212.3.25"
QRADAR_SEC_TOKEN = "12622cc0-bc6c-4e07-becb-884ccada0deb".strip()

def upload_to_qradar(rule_content):
    """Qaydanı QRadar API-sinə POST edir"""
    q_url = f"https://{QRADAR_IP}/api/analytics/rules"
    headers = {
        "SEC": QRADAR_SEC_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    try:
        # verify=False QRadar-ın self-signed sertifikatı üçündür
        response = requests.post(q_url, headers=headers, data=rule_content, verify=False, timeout=10)
        return response.status_code in [200, 201], response.status_code
    except Exception as e:
        return False, str(e)

def start_deploy():
    # GitHub Headerləri (User-Agent mütləqdir!)
    gh_headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "QRadar-Rule-Deployer" 
    }

    print("--- Əməliyyat Başladı ---")
    print(f"[*] GitHub API-yə müraciət edilir...")

    try:
        res = requests.get(GITHUB_REPO_API, headers=gh_headers, timeout=10)
        
        # Əgər hələ də 401 verirsə, GitHub-ın cavabını tam çap edirik ki, sirr qalmasın
        if res.status_code != 200:
            print(f"[X] GitHub Xətası! Status: {res.status_code}")
            print(f"[!] Mesaj: {res.text}")
            return

        items = res.json()
        
        # Əgər göstərilən yol tək bir fayldırsa
        if isinstance(items, dict):
            items = [items]

        count = 0
        for item in items:
            if item['type'] == 'file' and item['name'].endswith('.json'):
                rule_name = item['name']
                download_url = item['download_url']
                
                print(f"[*] İşlənir: {rule_name}")
                
                # Faylı GitHub-dan oxuyuruq
                file_res = requests.get(download_url, headers=gh_headers, timeout=10)
                
                if file_res.status_code == 200:
                    # QRadar-a göndəririk
                    success, status = upload_to_qradar(file_res.text)
                    if success:
                        print(f"  [✔] {rule_name} QRadar-a uğurla yükləndi.")
                        count += 1
                    else:
                        print(f"  [!] {rule_name} QRadar-a göndərilə bilmədi. Xəta: {status}")
        
        print(f"\n--- Yekun: {count} qayda uğurla deploy edildi. ---")

    except Exception as e:
        print(f"[X] Gözlənilməz xəta: {str(e)}")

if __name__ == "__main__":
    start_deploy()
