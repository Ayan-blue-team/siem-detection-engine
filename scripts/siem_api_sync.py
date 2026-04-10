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
                    # Tokenin təmiz olduğundan əmin oluruq
                    headers = {'Authorization': f'Bearer {splunk_token.strip()}'}
                    data = {'name': rule_name, 'search': query, 'disabled': '0'}
                    
                    print(f"Splunk-a göndərilir: {rule_name}")
                    
                    url = f"{splunk_url}/services/saved/searches"
                    response = requests.post(url, data=data, headers=headers, verify=False)

                    if response.status_code in [200, 201]:
                        print(f"Uğurla yaradıldı: {rule_name}")
                        acl_url = f"{splunk_url}/services/saved/searches/{rule_name}/acl"
                        acl_data = {'sharing': 'global', 'owner': 'admin'}
                        requests.post(acl_url, data=acl_data, headers=headers, verify=False)
                    else:
                        print(f"Splunk xətası ({response.status_code}): {response.text}")

def deploy_qradar_rules():
    qradar_url = os.getenv('QRADAR_URL')
    # URL-in sonundakı lazımsız / işarəsini təmizləyirik
    qradar_url = qradar_url.rstrip('/')
    qradar_token = os.getenv('QRADAR_TOKEN')
    rule_path = "qradar/aql_queries/"
    
    if os.path.exists(rule_path):
        files = [f for f in os.listdir(rule_path) if f.endswith(".aql")]
        print(f"DEBUG: QRadar qovluğunda tapılan .aql faylları: {files}")
        
        for filename in files:
            with open(os.path.join(rule_path, filename), 'r') as f:
                query = f.read()
                rule_name = filename.replace(".aql", "")
                
                # QRadar API-da SEC token boşluqsuz olmalıdır
                headers = {
                    'SEC': qradar_token.strip(), 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                # QRadar bəzən 'base_query' əvəzinə fərqli JSON strukturu istəyir.
                # Ən standart 'Custom Rule' (ADE) formatı:
                data = {
                    "name": rule_name,
                    "type": "ADE",
                    "enabled": True,
                    "base_query": query
                }
                
                print(f"QRadar-a göndərilir: {rule_name}")
                
                # URL-i dəyişib yenidən yoxlayırıq
                endpoint = f"{qradar_url}/api/analytics/rules"
                response = requests.post(endpoint, json=data, headers=headers, verify=False)
                
                if response.status_code in [200, 201]:
                    print(f"QRadar-da uğurla yaradıldı: {rule_name}")
                elif response.status_code == 404:
                    print(f"QRadar xətası (404): Endpoint tapılmadı. Zəhmət olmasa API interfeysindən POST /analytics/rules yolunu yoxlayın.")
                else:
                    print(f"QRadar xətası ({response.status_code}): {response.text}")

if __name__ == "__main__":
    print("--- Avtomatlaşdırma Başladı ---")
    deploy_splunk_rules()  
    deploy_qradar_rules()   
    print("--- Proses Bitdi ---")
