import requests
import json
import urllib3

# QRadar özü-imzaladığı sertifikat işlətdiyi üçün xəbərdarlıqları bağlayırıq
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONFİQURASİYA ---
# 1. GitHub Ayarları
GITHUB_TOKEN = "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  "
# Nümunə API URL: https://api.github.com/repos/user/repo/contents/folder
GITHUB_REPO_API = "https://api.github.com/repos/Ayan-blue-team/siem-detection-engine/contents/qradar/rules"

# 2. QRadar Ayarları
QRADAR_IP = "18.212.3.25" # QRadar Console IP
QRADAR_SEC_TOKEN = "12622cc0-bc6c-4e07-becb-884ccada0deb"

# --- FUNKSİYALAR ---

def upload_to_qradar(rule_content):
    """Qaydanı QRadar API-sinə göndərir"""
    q_url = f"https://{QRADAR_IP}/api/analytics/rules"
    headers = {
        "SEC": QRADAR_SEC_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    try:
        response = requests.post(q_url, headers=headers, data=rule_content, verify=False)
        if response.status_code == 201 or response.status_code == 200:
            return True, response.status_code
        else:
            return False, response.text
    except Exception as e:
        return False, str(e)

def process_github_to_qradar():
    gh_headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    print(f"[*] GitHub-dan qaydalar siyahısı alınır...")
    gh_res = requests.get(GITHUB_REPO_API, headers=gh_headers)
    
    if gh_res.status_code != 200:
        print(f"[X] GitHub API xətası: {gh_res.status_code}")
        return

    rules = gh_res.json()
    
    for item in rules:
        if item['type'] == 'file' and item['name'].endswith('.json'):
            file_name = item['name']
            download_url = item['download_url']
            
            print(f"[*] İşlənir: {file_name}")
            
            # Faylın içindəki datanı GitHub-dan oxu
            file_res = requests.get(download_url, headers=gh_headers)
            if file_res.status_code == 200:
                rule_data = file_res.text # Qaydanın JSON mətni
                
                # Birbaşa QRadar-a yüklə
                success, status_or_error = upload_to_qradar(rule_data)
                
                if success:
                    print(f"  [✔] {file_name} uğurla QRadar-a yükləndi (Status: {status_or_error})")
                else:
                    print(f"  [!] {file_name} yüklənə bilmədi. Xəta: {status_or_error}")
            else:
                print(f"  [!] GitHub-dan fayl oxuna bilmədi: {file_name}")

if __name__ == "__main__":
    print("--- GitHub to QRadar Automation Tool ---")
    process_github_to_qradar()
    print("\n--- Əməliyyat Başa Çatdı ---")
