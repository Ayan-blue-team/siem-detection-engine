import requests
import base64
import os
import json
import urllib3

# SSL xəbərdarlıqlarını gizlədir (özünüzün lab mühiti üçün)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GH_TOKEN      = os.environ.get("GH_TOKEN")
GH_REPO_OWNER = os.environ.get("GH_REPO_OWNER")
GH_REPO_NAME  = os.environ.get("GH_REPO_NAME")
GH_BRANCH     = os.environ.get("GH_BRANCH", "main")
QRADAR_HOST   = os.environ.get("QRADAR_HOST")
QRADAR_TOKEN  = os.environ.get("QRADAR_TOKEN")

def gh_headers():
    return {
        "Authorization": f"token {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

def github_list_files(path):
    url = f"https://api.github.com/repos/{GH_REPO_OWNER}/{GH_REPO_NAME}/contents/{path}?ref={GH_BRANCH}"
    r = requests.get(url, headers=gh_headers())
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return r.json()

def github_read_file(file_url):
    r = requests.get(file_url, headers=gh_headers())
    r.raise_for_status()
    return base64.b64decode(r.json()["content"]).decode("utf-8")

def qradar_headers():
    return {
        "SEC": QRADAR_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": "7.5.0",
    }

def qradar_deploy(name, aql_text):
    # Offense yaradılması üçün tam konfiqurasiya
    rule_data = {
        "name": name,
        "type": "EVENT",
        "enabled": True,
        "origin": "USER",
        "owner": "admin",
        "rule_type": "COMMON",
        "rule_contexts": ["EV"],
        "magnitude": 5,
        "severity": 5,
        "responses": [
            {
                "type": "dispatchNewOffense",
                "parameters": [
                    { "name": "offenseName", "value": f"Alert: {name}" },
                    { "name": "offenseType", "value": "event" }
                ]
            }
        ],
        "text": aql_text
    }

    url = f"{QRADAR_HOST}/api/analytics/rules"
    r = requests.post(url, headers=qradar_headers(), json=rule_data, verify=False)

    if r.status_code in (200, 201):
        print(f"  [QRadar] Uğurla yaradıldı (Offense aktivdir): {name}")
    else:
        print(f"  [QRadar] XƏTA {r.status_code}: {name} - {r.text[:300]}")

def deploy_qradar():
    print("\n  -> qradar/aql_queries/ oxunur...")
    files = github_list_files("qradar/aql_queries")
    count = 0
    for f in files:
        if not f["name"].endswith(".aql"):
            continue
        rule_name = f["name"].replace(".aql", "")
        aql_text  = github_read_file(f["url"]).strip()
        print(f"    -> {f['name']}")
        qradar_deploy(rule_name, aql_text)
        count += 1
    print(f"  [QRadar] Cemi {count} rule islendi.")

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  QRadar Detection-as-Code Deployment")
    print("="*55)
    deploy_qradar()
    print("\n" + "="*55 + "\n")
