import requests
import yaml
import base64
import os
from pathlib import Path

# ── Config ────────────────────────────────────────────────────
def load_config():
    config_path = Path(__file__).parent.parent / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f)
    # GitHub Actions — environment variable-lardan oxu
    return {
        "github": {
            "repo_owner": os.environ.get("GH_REPO_OWNER"),
            "repo_name":  os.environ.get("GH_REPO_NAME"),
            "branch":     os.environ.get("GH_BRANCH", "main"),
            "token":      os.environ.get("GH_TOKEN"),
        },
        "splunk": {
            "host":  os.environ.get("SPLUNK_HOST"),
            "token": os.environ.get("SPLUNK_TOKEN"),
            "app":   os.environ.get("SPLUNK_APP", "search"),
        },
        "qradar": {
            "host":       os.environ.get("QRADAR_HOST"),
            "token":      os.environ.get("QRADAR_TOKEN"),
            "verify_ssl": False,
        },
    }

cfg = load_config()
GH  = cfg["github"]
SPL = cfg["splunk"]
QR  = cfg["qradar"]

# ══════════════════════════════════════════════════════════════
# GITHUB
# ══════════════════════════════════════════════════════════════
def gh_headers():
    return {
        "Authorization": f"token {GH['token']}",
        "Accept": "application/vnd.github.v3+json"
    }

def github_list_files(path: str) -> list:
    url = (f"https://api.github.com/repos/{GH['repo_owner']}/"
           f"{GH['repo_name']}/contents/{path}?ref={GH['branch']}")
    r = requests.get(url, headers=gh_headers())
    if r.status_code == 404:
        print(f"  [GitHub] Path tapılmadı: {path}")
        return []
    r.raise_for_status()
    return r.json()

def github_read_file(file_url: str) -> str:
    r = requests.get(file_url, headers=gh_headers())
    r.raise_for_status()
    return base64.b64decode(r.json()["content"]).decode("utf-8")

# ══════════════════════════════════════════════════════════════
# SPLUNK — splunk/security/ altındakı .spl faylları
# ══════════════════════════════════════════════════════════════
def splunk_deploy(name: str, search_query: str):
    base    = f"{SPL['host']}/servicesNS/nobody/{SPL['app']}/saved/searches"
    headers = {"Authorization": f"Bearer {SPL['token']}"}

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
        print(f"  [Splunk] ERROR {r.status_code}: {name} — {r.text[:200]}")

def deploy_splunk():
    print("\n  → splunk/security/ qovluğu oxunur...")
    files = github_list_files("splunk/security")
    count = 0
    for f in files:
        if not f["name"].endswith(".spl"):
            continue
        rule_name    = f["name"].replace(".spl", "")
        search_query = github_read_file(f["url"]).strip()
        print(f"    → {f['name']}")
        splunk_deploy(rule_name, search_query)
        count += 1
    print(f"  [Splunk] Cəmi {count} rule işləndi.")

# ══════════════════════════════════════════════════════════════
# QRADAR — qradar/aql_queries/ altındakı .aql faylları
# ══════════════════════════════════════════════════════════════
def qradar_headers():
    return {
        "SEC":          QR["token"],
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "Version":      "14.0",
    }

def qradar_existing_rules() -> dict:
    url = f"{QR['host']}/api/analytics/rules?fields=id,name"
    r = requests.get(
        url, headers=qradar_headers(),
        verify=QR.get("verify_ssl", False)
    )
    r.raise_for_status()
    return {rule["name"]: rule["id"] for rule in r.json()}

def qradar_deploy(name: str, aql_text: str):
    existing = qradar_existing_rules()

    rule_data = {
        "name":        name,
        "type":        "EVENT",
        "enabled":     True,
        "origin":      "USER",
        "owner":       "admin",
        "rule_type":   "COMMON",
        "rule_contexts": ["EV"],
        "responses": [
            {
                "type": "OFFENSE",
                "contributing_credibility": 3,
                "contributing_severity":    5,
            }
        ],
        "text": aql_text,
    }

    if name in existing:
        rule_id = existing[name]
        url = f"{QR['host']}/api/analytics/rules/{rule_id}"
        r = requests.post(
            url, headers=qradar_headers(),
            json=rule_data,
            verify=QR.get("verify_ssl", False)
        )
        action = "UPDATED"
    else:
        url = f"{QR['host']}/api/analytics/rules"
        r = requests.post(
            url, headers=qradar_headers(),
            json=rule_data,
            verify=QR.get("verify_ssl", False)
        )
        action = "CREATED"

    if r.status_code in (200, 201):
        print(f"  [QRadar] {action}: {name}")
    else:
        print(f"  [QRadar] ERROR {r.status_code}: {name} — {r.text[:300]}")

def deploy_qradar():
    print("\n  → qradar/aql_queries/ qovluğu oxunur...")
    files = github_list_files("qradar/aql_queries")
    count = 0
    for f in files:
        if not f["name"].endswith(".aql"):
            continue
        rule_name = f["name"].replace(".aql", "")
        aql_text  = github_read_file(f["url"]).strip()
        print(f"    → {f['name']}")
        qradar_deploy(rule_name, aql_text)
        count += 1
    print(f"  [QRadar] Cəmi {count} rule işləndi.")

# ══════════════════════════════════════════════════════════════
# ANA AXIŞI
# ══════════════════════════════════════════════════════════════
def main():
    print("\n" + "="*55)
    print("  GitHub → Splunk + QRadar  |  siem_api_sync.py")
    print("="*55)

    print("\n[1/2] Splunk deployment başlayır...")
    deploy_splunk()

    print("\n[2/2] QRadar deployment başlayır...")
    deploy_qradar()

    print("\n" + "="*55)
    print("  Deployment tamamlandı!")
    print("="*55 + "\n")

if __name__ == "__main__":
    main()
