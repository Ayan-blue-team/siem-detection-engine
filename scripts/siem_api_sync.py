import requests
import base64
import os
import json
import urllib3

# SSL xəbərdarlıqlarını gizlədir
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GH_TOKEN      = os.environ.get("GH_TOKEN")
GH_REPO_OWNER = os.environ.get("GH_REPO_OWNER")
GH_REPO_NAME  = os.environ.get("GH_REPO_NAME")
GH_BRANCH     = os.environ.get("GH_BRANCH", "main")
QRADAR_HOST   = os.environ.get("QRADAR_HOST")
QRADAR_TOKEN  = os.environ.get("QRADAR_TOKEN")

def qradar_headers():
    return {
        "SEC": QRADAR_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": "14.0",
    }

def qradar_deploy(name, aql_text):
    # Bu struktur QRadar-ın "Offense Rules" bölməsi üçün optimallaşdırılıb
    rule_data = {
        "name": name,
        "type": "EVENT",
        "enabled": True,
        "origin": "USER",
        "owner": "admin",
        "rule_type": "OFFENSE", 
        "rule_contexts": ["EV"],
        "magnitude": 5,
        "severity": 5,
        "base_event_count": 1,
        "group": "Default",
        "responses": [
            {
                "type": "dispatchNewOffense",
                "parameters": [
                    { "name": "offenseName", "value": f"Alert: {name}" },
                    { "name": "offenseType", "value": "event" },
                    { "name": "offenseDescription", "value": f"Avtomatik yaradılmış offense qaydası: {name}" }
                ]
            }
        ],
        "text": aql_text
    }

    url = f"{QRADAR_HOST}/api/analytics/rules"
    r = requests.post(url, headers=qradar_headers(), json=rule_data, verify=False)

    if r.status_code in (200, 201):
        print(f"  [QRadar] Uğurla yaradıldı: {name}")
    else:
        # Xətanı terminalda görmək üçün:
        print(f"  [QRadar] XƏTA {r.status_code}: {name}")
        print(f"  [QRadar] Detal: {r.text[:500]}")

# GitHub-dan faylları oxumaq üçün köməkçi funksiyalar
def gh_headers():
    return {"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"}

def github_list_files(path):
    url = f"https://api.github.com/repos/{GH_REPO_OWNER}/{GH_REPO_NAME}/contents/{path}?ref={GH_BRANCH}"
    r = requests.get(url, headers=gh_headers())
    return r.json() if r.status_code == 200 else []

def github_read_file(file_url):
    r = requests.get(file_url, headers=gh_headers())
    return base64.b64decode(r.json()["content"]).decode("utf-8")

def deploy_qradar():
    print("\n  -> qradar/aql_queries/ oxunur...")
    files = github_list_files("qradar/aql_queries")
    for f in files:
        if f["name"].endswith(".aql"):
            rule_name = f["name"].replace(".aql", "")
            aql_text = github_read_file(f["url"]).strip()
            print(f"    -> Deploy olunur: {rule_name}")
            qradar_deploy(rule_name, aql_text)

if __name__ == "__main__":
    deploy_qradar()
