#!/usr/bin/env python3
"""
qradar_extension_deploy.py
GitHub Actions → QRadar Extension Management API
POST /api/config/extension_management/extensions
"""

import os
import sys
import json
import zipfile
import tempfile
import requests
import urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ENV ──────────────────────────────────────────────────────────────
QRADAR_HOST  = os.environ.get("QRADAR_HOST", "").rstrip("/")
QRADAR_TOKEN = os.environ.get("QRADAR_TOKEN", "")
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

def get_existing_extension(name: str) -> dict | None:
    """Mövcud extension-ı adına görə tapır."""
    url = f"{QRADAR_HOST}/api/config/extension_management/extensions"
    r = requests.get(url, headers=qradar_headers(), verify=False, timeout=30)
    if r.status_code != 200:
        return None
    for ext in r.json():
        if ext.get("name") == name:
            return ext
    return None

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
        task_id = result.get("id") or result.get("task_id")
        print(f"  [QRadar] Extension upload OK — Task ID: {task_id}")
        return task_id
    else:
        print(f"  [QRadar] ERROR {r.status_code}: {r.text[:400]}")
        sys.exit(1)

def wait_for_task(task_id: int, retries: int = 20):
    """Install task-ın tamamlanmasını gözləyir."""
    import time
    url = f"{QRADAR_HOST}/api/config/extension_management/extensions/task_status/{task_id}"
    for i in range(retries):
        r = requests.get(url, headers=qradar_headers(), verify=False, timeout=30)
        if r.status_code == 200:
            status = r.json().get("status", "UNKNOWN")
            print(f"  [QRadar] Task {task_id} status: {status} ({i+1}/{retries})")
            if status in ("COMPLETED", "COMPLETE"):
                print("  [QRadar] ✅ Extension uğurla install edildi!")
                return True
            elif status in ("FAILED", "ERROR"):
                print(f"  [QRadar] ❌ Install failed: {r.json()}")
                sys.exit(1)
        time.sleep(5)
    print("  [QRadar] ⚠️  Timeout — task hələ davam edir, QRadar-dan yoxlayın.")
    return False

def install_extension(task_id: int):
    """Upload sonrası extension-ı aktiv edir."""
    url = f"{QRADAR_HOST}/api/config/extension_management/extensions/{task_id}"
    payload = {"action_type": "INSTALL"}
    headers = {**qradar_headers(), "Content-Type": "application/json"}
    r = requests.post(url, headers=headers, json=payload, verify=False, timeout=60)
    if r.status_code in (200, 201, 202):
        install_task = r.json().get("id")
        print(f"  [QRadar] Install task başladı — ID: {install_task}")
        return install_task
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
    task_id = deploy_extension(zip_path)

    print(f"\n[3/4] Extension install edilir...")
    install_task = install_extension(task_id)
    wait_for_task(install_task)

    print(f"\n[4/4] Rule-lar yoxlanılır...")
    verify_rules()

    print("\n" + "="*60)
    print("  ✅ Deploy tamamlandı!")
    print("  QRadar → Offense → Rules bölməsindən yoxlayın.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
