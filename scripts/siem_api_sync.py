import requests
import base64
import os

GH_TOKEN      = os.environ.get("GH_TOKEN")
GH_REPO_OWNER = os.environ.get("GH_REPO_OWNER")
GH_REPO_NAME  = os.environ.get("GH_REPO_NAME")
GH_BRANCH     = os.environ.get("GH_BRANCH", "main")

SPLUNK_HOST   = os.environ.get("SPLUNK_HOST")
SPLUNK_TOKEN  = os.environ.get("SPLUNK_TOKEN")
SPLUNK_APP    = os.environ.get("SPLUNK_APP", "search")

QRADAR_HOST   = os.environ.get("QRADAR_HOST")
QRADAR_TOKEN  = os.environ.get("QRADAR_TOKEN")

def gh_headers():
    return {
        "Authorization": f"token {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

def github_list_files(path):
    url = (f"https://api.github.com/repos/{GH_REPO_OWNER}/"
           f"{GH_REPO_NAME}/contents/{path}?ref={GH_BRANCH}")
    r = requests.get(url, headers=gh_headers())
    if r.status_code == 404:
        print(f"  [GitHub] Path tapilmadi: {path}")
        return []
    r.raise_for_status()
    return r.json()

def github_read_file(file_url):
    r = requests.get(file_url, headers=gh_headers())
    r.raise_for_status()
    return base64.b64decode(r.json()["content"]).decode("utf-8")

def splunk_deploy(name, search_query):
    base = f"{SPLUNK_HOST}/servicesNS/nobody/{SPLUNK_APP}/saved/searches"
    headers = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}

    exists = requests.get(
        f"{base}/{requests.utils.quote(name)}",
        headers=headers, verify=False
    )

    payload = {
        "name":                   name,
        "search":                 search_query,
        "cron_schedule":          "*/10 * * * *",
        "is_scheduled":           "1",
        "dispatch.earliest_time": "-10m",
        "dispatch.latest_time":   "now",
        "alert_type":             "number of events",
        "alert_comparator":       "greater than",
        "alert_threshold":        "0",
        "alert.severity":         "3",
        "alert.track":            "1",
    }

    if exists.status_code == 200:
        r = requests.post(
            f"{base}/{requests.utils.quote(name)}",
            headers=headers, data=payload, verify=False
        )
        action = "UPDATED"
    else:
        r = requests.post(
            base, headers=headers, data=payload, verify=False
        )
        action = "CREATED"

    if r.status_code in (200, 201):
        print(f"  [Splunk] {action}: {name}")
    else:
        print(f"  [Splunk] ERROR {r.status_code}: {name} - {r.text[:200]}")

def deploy_splunk():
    print("\n  -> splunk/security/ oxunur...")
    files = github_list_files("splunk/security")
    count = 0
    for f in files:
        if not f["name"].endswith(".spl"):
            continue
        rule_name    = f["name"].replace(".spl", "")
        search_query = github_read_file(f["url"]).strip()
        print(f"    -> {f['name']}")
        splunk_deploy(rule_name, search_query)
        count += 1
    print(f"  [Splunk] Cemi {count} rule islendi.")

def qradar_headers():
    return {
        "SEC":          QRADAR_TOKEN,
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "Version":      "14.0",
    }

def qradar_existing_rules():
    url = f"{QRADAR_HOST}/api/analytics/rules?fields=id,name"
    r = requests.get(url, headers=qradar_headers(), verify=False)
    r.raise_for_status()
    return {rule["name"]: rule["id"] for rule in r.json()}

def qradar_deploy(name, aql_text):
    existing = qradar_existing_rules()

    rule_data = {
        "name":          name,
        "type":          "EVENT",
        "enabled":       True,
        "origin":        "USER",
        "owner":         "admin",
        "rule_type":     "COMMON",
        "rule_contexts": ["EV"],
        "responses": [
            {
                "type":                     "OFFENSE",
                "contributing_credibility": 3,
                "contributing_severity":    5,
            }
        ],
        "text": aql_text,
    }

    if name in existing:
        rule_id = existing[name]
        url = f"{QRADAR_HOST}/api/analytics/rules/{rule_id}"
        r = requests.post(
            url, headers=qradar_headers(),
            json=rule_data, verify=False
        )
        action = "UPDATED"
    else:
        url = f"{QRADAR_HOST}/api/analytics/rules"
        r = requests.post(
            url, headers=qradar_headers(),
            json=rule_data, verify=False
        )
        action = "CREATED"

    if r.status_code in (200, 201):
        print(f"  [QRadar] {action}: {name}")
    else:
        print(f"  [QRadar] ERROR {r.status_code}: {name} - {r.text[:300]}")

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

def main():
    print("\n" + "="*55)
    print("  GitHub -> Splunk + QRadar  |  siem_api_sync.py")
    print("="*55)

    print("\n[1/2] Splunk deployment baslayir...")
    deploy_splunk()

    print("\n[2/2] QRadar deployment baslayir...")
    deploy_qradar()

    print("\n" + "="*55)
    print("  Deployment tamamlandi!")
    print("="*55 + "\n")

if __name__ == "__main__":
    main()
