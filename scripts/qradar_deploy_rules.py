import requests
token = "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".strip()
res = requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {token}"})
print(f"Status: {res.status_code}")
if res.status_code == 200: print(f"Token düzdür! İstifadəçi: {res.json()['login']}")
else: print("Token səhvdir! GitHub-dan yenisini al (icazələri yoxla).")
