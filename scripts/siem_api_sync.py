import os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── SPLUNK ────────────────────────────────────────────────────────────────────

def deploy_splunk_rules():
    splunk_url = os.getenv('SPLUNK_URL')
    splunk_token = os.getenv('SPLUNK_TOKEN')
    rule_path = "splunk/security/"

    if not splunk_url or not splunk_token:
        print("SPLUNK_URL və ya SPLUNK_TOKEN təyin edilməyib, keçilir.")
        return

    if not os.path.exists(rule_path):
        print(f"Splunk rule qovluğu tapılmadı: {rule_path}")
        return

    headers = {'Authorization': f'Bearer {splunk_token.strip()}'}

    for filename in os.listdir(rule_path):
        if not filename.endswith(".spl"):
            continue

        with open(os.path.join(rule_path, filename), 'r') as f:
            query = f.read()

        rule_name = filename.replace(".spl", "")
        print(f"Splunk-a göndərilir: {rule_name}")

        # Əvvəlcə rule mövcuddurmu yoxlayırıq
        check_url = f"{splunk_url}/services/saved/searches/{requests.utils.quote(rule_name, safe='')}"
        check_resp = requests.get(check_url, headers=headers, verify=False)

        if check_resp.status_code == 200:
            # Rule mövcuddur → PUT ilə update et
            update_url = f"{splunk_url}/services/saved/searches/{requests.utils.quote(rule_name, safe='')}"
            data = {'search': query, 'disabled': '0'}
            response = requests.post(update_url, data=data, headers=headers, verify=False)
            action = "Update"
        else:
            # Rule yoxdur → POST ilə yarat
            create_url = f"{splunk_url}/services/saved/searches"
            data = {'name': rule_name, 'search': query, 'disabled': '0'}
            response = requests.post(create_url, data=data, headers=headers, verify=False)
            action = "Yarat"

        if response.status_code in [200, 201]:
            print(f"  [{action}] Uğurlu: {rule_name}")
            # Global paylaşım üçün ACL tənzimləməsi
            acl_url = f"{splunk_url}/services/saved/searches/{requests.utils.quote(rule_name, safe='')}/acl"
            requests.post(acl_url, data={'sharing': 'global', 'owner': 'admin'}, headers=headers, verify=False)
        else:
            print(f"  [XƏTA] {rule_name} ({response.status_code}): {response.text}")


# ─── QRADAR ────────────────────────────────────────────────────────────────────

def get_qradar_existing_rules(qradar_url, headers):
    """QRadar-dakı mövcud rule-ları çəkir, adlarını id ilə map edir."""
    url = f"{qradar_url}/api/analytics/rules"
    params = {"fields": "id,name", "filter": "origin=USER"}
    try:
        resp = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
        if resp.status_code == 200:
            return {r["name"]: r["id"] for r in resp.json()}
        else:
            print(f"  [XƏTA] Mövcud rule-lar çəkiləmədi: {resp.status_code} — {resp.text}")
            return {}
    except Exception as e:
        print(f"  [XƏTA] QRadar bağlantı problemi: {e}")
        return {}


def build_qradar_payload(rule_name, rule_data):
    """
    QRadar /api/analytics/rules POST üçün düzgün payload strukturu.
    QRadar-ın Rules API-si tam rule obyekti deyil, rule expression qəbul edir.
    Offense yaratmaq üçün rule responses da əlavə edilir.
    """
    # rule_data JSON faylından gəlir (bizim rule_XX.json faylları)
    offense = rule_data.get("qradar_rule", {}).get("offense_settings", {})
    notes   = rule_data.get("qradar_rule", {}).get("notes", "")

    payload = {
        "name": rule_data.get("name", rule_name),
        "type": "EVENT",
        "enabled": rule_data.get("enabled", True),
        "owner": "admin",
        "notes": notes,
        "origin": "USER",
        "base_host_id": 0,
        "rule_responses": [
            {
                "type": "OFFENSE",
                "override_offense_description": True,
                "offense_type": offense.get("offense_type", "Source IP"),
                "description": offense.get("message", rule_data.get("description", "")),
                "name": rule_data.get("name", rule_name),
                "include_attack_chain_in_offenses": False,
                "override_offense_closing_reason_id": None
            }
        ],
        "rule_conditions": {
            "type": "CRE_RULE_CONDITION_BLOCK",
            "condition_block_type": "AND",
            "conditions": []
        },
        "severity_coefficient": rule_data.get("severity", 5),
        "group_ids": []
    }
    return payload


def deploy_qradar_rules():
    qradar_url   = os.getenv('QRADAR_URL', '').rstrip('/')
    qradar_token = os.getenv('QRADAR_TOKEN', '').strip()
    rule_path    = "rules/"   # bizim rule_XX.json faylları

    if not qradar_url or not qradar_token:
        print("QRADAR_URL və ya QRADAR_TOKEN təyin edilməyib, keçilir.")
        return

    if not os.path.exists(rule_path):
        print(f"QRadar rule qovluğu tapılmadı: {rule_path}")
        return

    headers = {
        'SEC': qradar_token,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Version': '20.0'
    }

    # Mövcud rule-ları çək (POST vs PUT qərarı üçün)
    print("QRadar-dakı mövcud rule-lar yoxlanılır...")
    existing = get_qradar_existing_rules(qradar_url, headers)
    print(f"  {len(existing)} mövcud custom rule tapıldı.")

    import json
    rule_files = sorted(f for f in os.listdir(rule_path) if f.endswith(".json"))
    print(f"DEBUG: rules/ qovluğunda tapılan fayllar: {rule_files}")

    for filename in rule_files:
        filepath = os.path.join(rule_path, filename)
        try:
            with open(filepath, 'r') as f:
                rule_data = json.load(f)
        except Exception as e:
            print(f"  [XƏTA] {filename} oxuna bilmədi: {e}")
            continue

        rule_name = rule_data.get("name", filename.replace(".json", ""))
        print(f"QRadar-a göndərilir: {rule_name}")

        payload = build_qradar_payload(filename, rule_data)

        try:
            if rule_name in existing:
                # Rule mövcuddur → PUT ilə update et
                rule_id  = existing[rule_name]
                endpoint = f"{qradar_url}/api/analytics/rules/{rule_id}"
                response = requests.put(endpoint, json=payload, headers=headers, verify=False, timeout=30)
                action   = "Update"
            else:
                # Rule yoxdur → POST ilə yarat
                endpoint = f"{qradar_url}/api/analytics/rules"
                response = requests.post(endpoint, json=payload, headers=headers, verify=False, timeout=30)
                action   = "Yarat"

            if response.status_code in [200, 201]:
                created = response.json()
                print(f"  [{action}] Uğurlu — ID: {created.get('id')} | {rule_name}")
            else:
                print(f"  [XƏTA] {rule_name} ({response.status_code}): {response.text}")

        except requests.exceptions.ConnectionError:
            print(f"  [XƏTA] QRadar-a qoşulmaq mümkün olmadı. URL-i yoxlayın: {qradar_url}")
            break
        except Exception as e:
            print(f"  [XƏTA] {rule_name}: {e}")


# ─── MAIN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("--- Avtomatlaşdırma Başladı ---")
    deploy_splunk_rules()
    deploy_qradar_rules()
    print("--- Proses Bitdi ---")
