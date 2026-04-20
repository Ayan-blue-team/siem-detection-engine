#!/usr/bin/env python3
"""
qradar_extension_deploy.py
GitHub Actions → QRadar Extension Management API
POST /api/config/extension_management/extensions
"""

import os
import sys
import json
import time
import zipfile
import tempfile
import requests
import urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ENV ──────────────────────────────────────────────────────────────
QRADAR_HOST   = os.environ.get("QRADAR_HOST", "").rstrip("/")
QRADAR_TOKEN  = os.environ.get("QRADAR_TOKEN", "")
EXTENSION_DIR = Path(__file__).parent.parent / "qradar" / "extension"

def qradar_headers():
    return {
        "SEC":     QRADAR_TOKEN,
        "Accept":  "application/json",
        "Version": "14.0",
    }

def build_extension_zip() -> str:
    """extension/ qovluğunu .zip-ə yığır, temp path qaytarır."""
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()

    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in EXTENSION_DIR.rglob("*"):
            if fpath.is_file():
                arcname = fpath.relative_to(EXTENSION_DIR)
                zf.write(fpath, arcname)
                print(f"  [ZIP] Added: {arcname}")

    size_kb = Path(tmp.name).stat().st_size / 1024
    print(f"  [ZIP] Built: {tmp.name} ({size_kb:.1f} KB)")
    return tmp.name

def deploy_extension(zip_path: str, overwrite: bool = True):
    """Extension zip-ini QRadar-a upload edir."""
    url = f"{QRADAR_HOST}/api/config/extension_management/extensions"
    params = {"overwrite": str(overwrite).lower()}

    with open(zip_path, "rb") as f:
        files = {"file": ("soc_offense_rules.zip", f, "application/zip")}
        headers = {
            "SEC":     QRADAR_TOKEN,
            "Accept":  "application/json",
            "Version": "14.0",
        }
        r = requests.post(
            url,
            headers=headers,
            params=params,
            files=files,
            verify=False,
            timeout=120,
        )

    if r.status_code in (200, 201, 202):
        result = r.json()
        print(f"  [QRadar] Upload response: {json.dumps(result, indent=2)}")
        upload_task_id = result.get("id") or result.get("task_id")
        print(f"  [QRadar] Upload Task ID: {upload_task_id}")
        return upload_task_id
    else:
        print(f"  [QRadar] ERROR {r.status_code}: {r.text[:400]}")
        sys.exit(1)

def wait_for_task(task_id: int, retries: int = 30):
    """Task-ın tamamlanmasını gözləyir, extension_id qaytarır."""
    url = f"{QRADAR_HOST}/api/config/extension_management/extensions/task_status/{task_id}"
    for i in range(retries):
        r = requests.get(url, headers=qradar_headers(), verify=False, timeout=30)
        if r.status_code == 200:
            data = r.json()
            status = data.get("status", "UNKNOWN")
            print(f"  [QRadar] Task {task_id} status: {status} ({i+1}/{retries})")

            if status in ("COMPLETED", "COMPLETE"):
                # QRadar 7.5.0-da extension_id belə gəlir
                extension_id = (
                    data.get("extension_id") or
                    data.get("extension", {}).get("id") or
                    data.get("id")
                )
                print(f"  [QRadar] ✅ Tamamlandı! Extension ID: {extension_id}")
                print(f"  [QRadar] Full response: {json.dumps(data, indent=2)}")
                return extension_id
            elif status in ("FAILED", "ERROR"):
                print(f"  [QRadar] ❌ Task failed: {json.dumps(data, indent=2)}")
                sys.exit(1)
        time.sleep(5)
    print("  [QRadar] ⚠️  Timeout!")
    return None

def install_extension(extension_id: int):
    """Extension-ı aktiv edir."""
    url = f"{QRADAR_HOST}/api/config/extension_management/extensions/{extension_id}"
    payload = {"action_type": "INSTALL"}
    headers = {**qradar_headers(), "Content-Type": "application/json"}

    r = requests.post(url, headers=headers, json=payload, verify=False, timeout=60)
    print(f"  [QRadar] Install response {r.status_code}: {r.text[:500]}")

    if r.status_code in (200, 201, 202):
        install_task_id = r.json().get("id")
        print(f"  [QRadar] Install task başladı — ID: {install_task_id}")
        return install_task_id
    else:
        print(f"  [QRadar] Install ERROR {r.status_code}: {r.text[:300]}")
        sys.exit(1)

def verify_rules():
    """Deploy sonrası rule-ların mövcudluğunu yoxlayır."""
    url = f"{QRADAR_HOST}/api/analytics/rules?fields=id,name,enabled,type&filter=name%20like%20%27SOC-QR%25%27"
    r = requests.get(url, headers=qradar_headers(), verify=False, timeout=30)
    if r.status_code == 200:
        rules = r.json()
        print(f"\n  [QRadar] ✅ Aktiv SOC rule-lar ({len(rules)} ədəd):")
        for rule in rules:
            status = "✅ ENABLED" if rule.get("enabled") else "⚠️  DISABLED"
            print(f"    {status} | {rule['name']}")
    else:
        print(f"  [QRadar] Rule yoxlama xətası: {r.status_code}")

def main():
    print("\n" + "="*60)
    print("  QRadar Extension Deploy | soc_offense_rules")
    print("="*60)

    if not QRADAR_HOST or not QRADAR_TOKEN:
        print("❌ QRADAR_HOST və QRADAR_TOKEN env dəyişənlərini təyin edin!")
        sys.exit(1)

    print(f"\n[1/4] Extension ZIP hazırlanır...")
    zip_path = build_extension_zip()

    print(f"\n[2/4] QRadar-a upload edilir ({QRADAR_HOST})...")
    upload_task_id = deploy_extension(zip_path)

    print(f"\n[2.5/4] Upload task gözlənilir...")
    extension_id = wait_for_task(upload_task_id)

    if not extension_id:
        print("❌ Extension ID alınmadı, dayandırılır.")
        sys.exit(1)

    print(f"\n[3/4] Extension install edilir (ID: {extension_id})...")
    install_task_id = install_extension(extension_id)
    wait_for_task(install_task_id)

    print(f"\n[4/4] Rule-lar yoxlanılır...")
    verify_rules()

    print("\n" + "="*60)
    print("  ✅ Deploy tamamlandı!")
    print("  QRadar → Offense → Rules bölməsindən yoxlayın.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
