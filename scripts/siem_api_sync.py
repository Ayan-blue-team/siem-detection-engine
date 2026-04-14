def build_qradar_payload(filename, rule_data):
    """QRadar API uyğun payload strukturu"""
    qradar_cfg = rule_data.get("qradar_rule", {})
    offense = qradar_cfg.get("offense_settings", {})
    
    # QRadar yalnız 'expression' (AQL) və ya düzgün 'cre_conditions' qəbul edir
    payload = {
        "name": rule_data.get("name", filename.replace(".json", "")),
        "description": rule_data.get("description", ""),
        "enabled": rule_data.get("enabled", True),
        "origin": "USER",
        "severity_coefficient": rule_data.get("severity", 5),
        "expression": rule_data.get("expression", "").strip(),  # AQL query
        "responses": [
            {
                "type": "OFFENSE",
                "name": offense.get("name", rule_data.get("name", "")),
                "description": offense.get("message", rule_data.get("description", "")),
                "offense_type": offense.get("offense_type", "Source IP")
            }
        ]
    }
    # Boş sahələri sil (QRadar 400 error verir)
    payload = {k: v for k, v in payload.items() if v not in [None, "", []]}
    return payload


def deploy_qradar_rules():
    qradar_url   = os.getenv('QRADAR_URL', '').rstrip('/')
    qradar_token = os.getenv('QRADAR_TOKEN', '').strip()
    rule_path    = "rules/"

    if not qradar_url or not qradar_token:
        print("QRADAR_URL və ya SPLUNK_TOKEN təyin edilməyib, keçilir.")
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
        
        # AQL boşdursa, rule yaradılmamalıdır
        if not payload.get("expression"):
            print(f"  [XƏTA] {rule_name} üçün 'expression' (AQL) tapılmadı. Keçilir.")
            continue

        try:
            if rule_name in existing:
                rule_id  = existing[rule_name]
                endpoint = f"{qradar_url}/api/analytics/rules/{rule_id}"
                response = requests.put(endpoint, json=payload, headers=headers, verify=False, timeout=30)
                action   = "Update"
            else:
                endpoint = f"{qradar_url}/api/analytics/rules"
                response = requests.post(endpoint, json=payload, headers=headers, verify=False, timeout=30)
                action   = "Yarat"

            if response.status_code in [200, 201]:
                res_json = response.json()
                print(f"  [{action}] Uğurlu — ID: {res_json.get('id')} | {rule_name}")
            else:
                print(f"  [XƏTA] {rule_name} ({response.status_code}): {response.text}")

        except requests.exceptions.ConnectionError:
            print(f"  [XƏTA] QRadar-a qoşulmaq mümkün olmadı. URL-i yoxlayın: {qradar_url}")
            break
        except Exception as e:
            print(f"  [XƏTA] {rule_name}: {e}")

    # ✅ VACİB: Rule-ları aktivləşdirmək üçün Deploy çağırışı
    print("\n📦 QRadar Deploy Changes başladılır...")
    deploy_qradar_changes(qradar_url, headers)


def deploy_qradar_changes(qradar_url, headers):
    """Yaradılan/Update edilən rule-ları QRadar-da aktivləşdirir"""
    try:
        resp = requests.post(f"{qradar_url}/api/siem/deploy", headers=headers, verify=False, timeout=60)
        if resp.status_code in [200, 202]:
            task_id = resp.json().get("id")
            print(f"✅ Deploy uğurlu! Task ID: {task_id}. QRadar rule-ları 1-2 dəqiqəyə aktiv olacaq.")
        else:
            print(f"❌ Deploy uğursuz ({resp.status_code}): {resp.text}")
    except Exception as e:
        print(f"❌ Deploy zamanı xəta: {e}")
