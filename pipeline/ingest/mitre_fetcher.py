import requests
import json

def fetch_mitre_cves():
    url = "https://cveawg.mitre.org/api/cve-id?page=1&pageSize=100&state=PUBLISHED"
    headers = {
        "CVE-API-ORG": "vuln-intel-feed",
        "CVE-API-USER": "dvij"
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    print(json.dumps(data, indent=2)[:500])  # show raw response first
    cve_ids = [item["cveId"] for item in data["cveIds"]]
    with open("data/raw/mitre_cves.json", "w") as f:
        json.dump(cve_ids, f)
    print(f"Fetched {len(cve_ids)} CVEs")

if __name__ == "__main__":
    fetch_mitre_cves()
