import requests
import json
import urllib3
import os

# QRadar sertifikat xəbərdarlıqlarını söndürürük
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- KONFİQURASİYA ---
# GitHub Personal Access Token (PAT)
GITHUB_TOKEN = "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" 

# GitHub API URL (DÜZGÜN FORMAT: https://api.github.com/repos/USER/REPO/contents/FOLDER)
GITHUB_REPO_API = "https://api.github.com/repos/Ayan-blue-team/siem-detection-engine/contents/qradar/rules"

# QRadar Ayarları
QRADAR_IP = "18.212.3.25"
QRADAR_SEC_TOKEN = "12622cc0-bc6c-4e07-becb-884ccada0deb"

def test_github_token():
    """Tokenin keçərli olub-olmadığını yoxlayır"""
    url = "https://api.github.com/user"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}", # 'token' əvəzinə 'Bearer' daha etibarlıdır
        "Accept": "application/vnd.github.v3+json"
    }
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        print(f"[✔] GitHub Token təsdiqləndi: {res.json().get('login')}")
        return True
    else:
        print(f"[X] Token Xətası (401): Token ya səhvdir, ya da vaxtı bitib.")
        return False

def upload_to_qradar(rule_content):
    q_url = f"https://{QRADAR_IP}/api/analytics/rules"
    headers = {
        "SEC": QRADAR_SEC_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    try:
        response = requests.post(q_url, headers=headers, data=rule_content, verify=False)
        return response.status_code in [200, 201], response.status_code
    except Exception as e:
        return False, str(e)

def process_rules():
    if not test_github_token():
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    print(f"[*] Qaydalar çəkilir: {GITHUB_REPO_API}")
    res = requests.get(GITHUB_REPO_API, headers=headers)
    
    if res.status_code != 200:
        print(f"[X] Qovluq oxuna bilmədi. Status: {res.status_code}, Mesaj: {res.text}")
        return

    items = res.json()
    for item in items:
        if item['type'] == 'file' and item['name'].endswith('.json'):
            f_name = item['name']
            f_url = item['download_url']
            
            print(f"[*] {f_name} emal edilir...")
            f_res = requests.get(f_url, headers=headers)
            
            if f_res.status_code == 200:
                success, status = upload_to_qradar(f_res.text)
                if success:
                    print(f"  [+] QRadar-a yükləndi: {f_name}")
                else:
                    print(f"  [!] QRadar xətası ({status}): {f_name}")

if __name__ == "__main__":
    process_rules()
