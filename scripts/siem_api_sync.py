import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def deploy_splunk_rules():
    splunk_url = os.getenv('SPLUNK_URL') 
    splunk_token = os.getenv('SPLUNK_TOKEN')
    rule_path = "splunk/security/"
    
    if os.path.exists(rule_path):
        for filename in os.listdir(rule_path):
            if filename.endswith(".spl"):
                with open(os.path.join(rule_path, filename), 'r') as f:
                    query = f.read()
                    rule_name = filename.replace(".spl", "")
                    headers = {'Authorization': f'Bearer {splunk_token}'}
                    data = {'name': rule_name, 'search': query, 'disabled': '0'}
                    
                    print(f"Splunk-a göndərilir: {rule_name}")
                    
                    # 1. Qaydanı yaradırıq
                    url = f"{splunk_url}/services/saved/searches"
                    response = requests.post(url, data=data, headers=headers, verify=False)

                    if response.status_code in [200, 201]:
                        print(f"Uğurla yaradıldı: {rule_name}")
                        
                        # 2. Paylaşım icazəsini GLOBAL edirik
                        acl_url = f"{splunk_url}/services/saved/searches/{rule_name}/acl"
                        acl_data = {'sharing': 'global', 'owner': 'admin'}
                        
                        acl_res = requests.post(acl_url, data=acl_data, headers=headers, verify=False)
                        
                        if acl_res.status_code == 200:
                            print(f"Paylaşım statusu: Global-a dəyişdirildi.")
                        else:
                            print(f"Paylaşım xətası: {acl_res.status_code}")
                    else:
                        # Əgər qayda artıq varsa, 409 xətası ala bilərsiniz
                        print(f"Splunk xətası ({response.status_code}): {response.text}")

def deploy_qradar_rules():
    qradar_url = os.getenv('QRADAR_URL')
    qradar_token = os.getenv('QRADAR_TOKEN')
    rule_path = "qradar/aql_queries/"
    
    if os.path.exists(rule_path):
        for filename in os.listdir(rule_path):
            if filename.endswith(".aql"):
                with open(os.path.join(rule_path, filename), 'r') as f:
                    query = f.read()
                    rule_name = filename.replace(".aql", "")
                    headers = {'SEC': qradar_token, 'Content-Type': 'application/json'}
                    data = {"name": rule_name, "type": "ADE", "enabled": True, "base_query": query}
                    
                    print(f"QRadar-a göndərilir: {rule_name}")
                    response = requests.post(f"{qradar_url}/api/analytics/rules", json=data, headers=headers, verify=False)
                    
                    if response.status_code in [200, 201]:
                        print(f"QRadar-da uğurla yaradıldı: {rule_name}")
                    else:
                        print(f"QRadar xətası ({response.status_code}): {response.text}")

if __name__ == "__main__":
    print("--- Avtomatlaşdırma Başladı ---")
    deploy_splunk_rules()  
    deploy_qradar_rules()   
    print("--- Proses Bitdi ---")
