import requests
import json
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import time

load_dotenv()

def fetch_nvd_cves(days_back=30):
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
        "startIndex": 0
    }
    all_cves = []
    while True:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        all_cves.extend(data.get("vulnerabilities", []))
        print(f"Fetched {len(all_cves)} / {data['totalResults']} CVEs")
        if len(all_cves) >= data.get("totalResults", 0):
            break
        params["startIndex"] += 2000
        time.sleep(1)
    with open("data/raw/nvd_cves.json", "w") as f:
        json.dump(all_cves, f)

if __name__ == "__main__":
    fetch_nvd_cves()
