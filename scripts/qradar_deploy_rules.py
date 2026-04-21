import requests
import json
import urllib3
import os

# QRadar sertifikat xəbərdarlıqlarını bağlayırıq
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- TOKENLƏRİN OXUNMASI ---
# GitHub Actions-da işləyirsə Secrets-dən çəkəcək.
# Lokalda işləyirsənsə, aşağıdakı dırnaqların içinə tokeni birbaşa yaz və TEST ET.
GITHUB_TOKEN = os.getenv("GH_TOKEN_SECRET") or "BURAYA_TEST_UCUN_TOKENI_YAZ_VE_PUSH_ETME"
QRADAR_SEC_TOKEN = os.getenv("QRADAR_SEC_TOKEN") or "BURAYA_TEST_UCUN_QRADAR_TOKENINI_YAZ"

# --- KONFİQURASİYA ---
# Diqqət: Bu URL-in doğruluğunu brauzerdə yoxla!
GITHUB_REPO_API = "https://api.github.com/repos/Ayan-blue-team/siem-detection-engine/contents/qradar/rules"
QRADAR_IP = "18.212.3.25"

def check_env():
    """Tokenlərin yüklənib-yüklənmədiyini yoxlayır"""
    if not GITHUB_TOKEN or "BURAYA" in GITHUB_TOKEN:
        print("[!] DİQQƏT: GitHub Tokeni tapılmadı və ya hələ də boşdur!")
        return False
    print(f"[*] GitHub Token tapıldı (Uzunluq: {len(GITHUB_TOKEN)} simvol)")
    return True

def deploy():
    if not check_env(): return

    gh_headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "QRadar-Auto-Deployer-v2"
    }

    print(f"[*] GitHub API-yə müraciət edilir: {GITHUB_REPO_API}")
    
    try:
        response = requests.get(GITHUB_REPO_API, headers=gh_headers)
        
        if response.status_code == 401:
            print("[X] GitHub Xətası 401: İcazə verilmir!")
            print(f"    Mesaj: {response.json().get('message')}")
            print("    Məsləhət: Tokeni yaradarkən 'repo' icazəsi verdiyindən və onu koda düzgün yapışdırdığından əmin ol.")
            return
        elif response.status_code != 200:
            print(f"[X] Gözlənilməz Xəta ({response.status_code}): {response.text}")
            return

        rules = response.json()
        print(f"[+] {len(rules)} element aşkar edildi. Yükləmə başlayır...")

        for item in rules:
            if item['type'] == 'file' and item['name'].endswith('.json'):
                # Rule məzmununu çək
                rule_res = requests.get(item['download_url'], headers=gh_headers)
                if rule_res.status_code == 200:
                    # QRadar-a göndər
                    q_headers = {"SEC": QRADAR_SEC_TOKEN, "Content-Type": "application/json"}
                    q_url = f"https://{QRADAR_IP}/api/analytics/rules"
                    
                    q_post = requests.post(q_url, headers=q_headers, data=rule_res.text, verify=False)
                    
                    if q_post.status_code in [200, 201]:
                        print(f"  [✔] Yükləndi: {item['name']}")
                    else:
                        print(f"  [!] QRadar Xətası ({q_post.status_code}): {item['name']}")

    except Exception as e:
        print(f"[X] Sistem Xətası: {str(e)}")

if __name__ == "__main__":
    deploy()
