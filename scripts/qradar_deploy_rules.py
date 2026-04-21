import requests
import json
import urllib3

# ============================================================
#  BURAYA OZ MELUMATLARINI YAZ
# ============================================================
QRADAR_IP  = "18.212.3.25"
AUTH_TOKEN = "12622cc0-bc6c-4e07-becb-884ccada0deb"
# ============================================================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = f"https://{QRADAR_IP}/api"

HEADERS = {
    "SEC": AUTH_TOKEN,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

RULES = [
    {
        "name": "Brute Force Login Attempt",
        "notes": "Eyni IP-den 5 deqiqe erzinde 10-dan cox ugursuz giris cehdi askar edilir.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "Suspicious Port Scan Detection",
        "notes": "Tek bir menbeden 60 saniye erzinde 50-den cox ferqli porta muraciet.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "Malware C2 Communication",
        "notes": "Daxili host-un bilinen C2 IP/domain siyahisi ile elaqesi askar edilir.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "Privileged Account After Hours Login",
        "notes": "Is saatlarindan kenar (22:00-07:00) admin hesabi ile giris.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "Large Data Exfiltration Attempt",
        "notes": "Daxili hostdan xerice 1 saatda 500MB-den cox data oturulmesi.",
        "type": "FLOW",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "SQL Injection Attack Detected",
        "notes": "Web server loglarinda SQL injection pattern-leri askar edilir.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "New Admin Account Created",
        "notes": "Is saatlari xericinde yeni administrator hesabi yaradilmasi.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "Ransomware File Encryption Pattern",
        "notes": "Qisa muddette coxlu faylin adinin deyisdirilmesi/sifrelenmesi.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "DNS Tunneling Detection",
        "notes": "Qeyri-adi olculu DNS sorqulari vasitesile data sizması cehdi.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    },
    {
        "name": "Lateral Movement via SMB",
        "notes": "Daxili sebекede bir hostdan digerine SMB protokolu ile yayilma cehdi.",
        "type": "EVENT",
        "enabled": True,
        "owner": "admin"
    }
]


def create_rule(rule):
    url = f"{BASE_URL}/analytics/rules"
    response = requests.post(url, headers=HEADERS, json=rule, verify=False)
    if response.status_code in [200, 201]:
        created = response.json()
        print(f"[OK] Rule yaradildi: {rule['name']} (ID: {created.get('id')})")
    else:
        print(f"[XETA] {rule['name']} -> {response.status_code}: {response.text}")


def main():
    print("=" * 55)
    print("QRadar Custom Offense Rules - Deploy Skripti")
    print("=" * 55)
    for rule in RULES:
        create_rule(rule)
    print("=" * 55)
    print("Proses tamamlandi.")


if __name__ == "__main__":
    main()
