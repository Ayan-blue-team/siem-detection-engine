import requests
import json
import urllib3
import os

# QRadar xəbərdarlıqlarını söndürürük
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- TOKENLƏRİ SİSTEMDƏN ÇƏKİRİK ---
# Bu sətirlər tokenləri "Secret" hissəsindən və ya terminaldan oxuyur
GITHUB_TOKEN = os.getenv("GH_TOKEN_SECRET")
QRADAR_SEC_TOKEN = os.getenv("QRADAR_SEC_TOKEN")

# --- KONFİQURASİYA ---
# Diqqət: Linki öz repo məlumatlarına görə dəyiş!
GITHUB_REPO_API = "https://api.github.com/repos/Ayan-blue-team/siem-detection-engine/contents/qradar/rules"
QRADAR_IP = "18.212.3.25"

def deploy():
    if not GITHUB_TOKEN or not QRADAR_SEC_TOKEN:
        print("[X] Xəta: Tokenlər tapılmadı! Mühit dəyişənlərini yoxla.")
        return

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "QRadar-DaC-Deployer"
    }

    print("[*] GitHub-dan qaydalar siyahısı alınır...")
    res = requests.get(GITHUB_REPO_API, headers=headers)

    if res.status_code != 200:
        print(f"[X] GitHub Giriş Xətası: {res.status_code}")
        return

    items = res.json()
    for item in items:
        if item['type'] == 'file' and item['name'].endswith('.json'):
            print(f"[*] Emal edilir: {item['name']}")
            
            # Faylı oxuyuruq
            file_res = requests.get(item['download_url'], headers=headers)
            if file_res.status_code == 200:
                # QRadar-a göndəririk
                q_headers = {
                    "SEC": QRADAR_SEC_TOKEN,
                    "Content-Type": "application/json"
                }
                q_url = f"https://{QRADAR_IP}/api/analytics/rules"
                
                q_post = requests.post(q_url, headers=q_headers, data=file_res.text, verify=False)
                
                if q_post.status_code in [200, 201]:
                    print(f"  [✔] Uğurla QRadar-a yükləndi.")
                else:
                    print(f"  [!] QRadar xətası ({q_post.status_code})")

if __name__ == "__main__":
    deploy()
