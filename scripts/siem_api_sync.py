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
                    requests.post(f"{splunk_url}/services/saved/searches", data=data, headers=headers, verify=False)


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
                    requests.post(f"{qradar_url}/api/analytics/rules", json=data, headers=headers, verify=False)


if __name__ == "__main__":
    print("--- Avtomatlaşdırma Başladı ---")
    deploy_splunk_rules()  
    deploy_qradar_rules()   
    print("--- Proses Bitdi ---")
