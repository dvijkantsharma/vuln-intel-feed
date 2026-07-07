import requests

def fetch_mitre_cves():
    url = "https://cveawg.mitre.org/api/cve-id?page=1&pageSize=100&state=PUBLISHED"
    response = requests.get(url)
    data = response.json()
    cve_ids = [item["cveId"] for item in data["result"]]
    with open("data/raw/mitre_cves.json", "w") as f:
        f.write(str(cve_ids))
    print(f"Fetched {len(cve_ids)} CVEs")

if __name__ == "__main__":
    fetch_mitre_cves()
