import requests
from datetime import datetime, timedelta

# 前一天（UTC）
yesterday = datetime.utcnow() - timedelta(days=1)

start_date = yesterday.strftime('%Y-%m-%dT00:00:00.000')
end_date   = yesterday.strftime('%Y-%m-%dT23:59:59.999')

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

params = {
    "pubStartDate": start_date,
    "pubEndDate": end_date
}

headers = {
    "User-Agent": "CVE-Fetch-Script"
    # "apiKey": "你的API KEY"
}

response = requests.get(url, params=params, headers=headers)
data = response.json()

vulns = data.get("vulnerabilities", [])

print(f"新發布 CVE 數量: {len(vulns)}")

for v in vulns[:10]:
    cve_id = v["cve"]["id"]
    desc = v["cve"]["descriptions"][0]["value"]
    print(cve_id, desc[:80])