import json

def extract_nvd_record(cve):
    id = cve["cve"]["id"]
    title = f"{id} Vulnerability"
    description = next((d["value"] for d in cve["cve"].get("descriptions", []) if d["lang"] == "en"), "")
    metrics = cve["cve"].get("metrics", {})
    cvss_score = None
    severity = None
    attack_vector = "UNKNOWN"
    for metric in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metric in metrics:
            metric_data = metrics[metric][0]
            cvss_score = metric_data["cvssData"]["baseScore"]
            severity = metric_data.get("baseSeverity") or metric_data["cvssData"].get("severity", "UNKNOWN")
            attack_vector = metric_data["cvssData"].get("attackVector", "UNKNOWN")
            break
    cwe_ids = [d["value"] for w in cve["cve"].get("weaknesses", []) for d in w.get("description", []) if d["value"].startswith("CWE-")]
    published_date = cve["cve"]["published"][:10]
    source = "nvd"
    tags = []
    raw = cve["cve"]
    return {
        "id": id,
        "title": title,
        "description": description,
        "source": source,
        "severity": severity,
        "cvss_score": cvss_score,
        "published_date": published_date,
        "attack_vector": attack_vector,
        "cwe_ids": cwe_ids,
        "tags": tags,
        "raw": raw
    }

def extract_arxiv_record(item):
    id = item["id"]
    title = item["title"]
    description = item["summary"]
    source = "arxiv"
    severity = None
    cvss_score = None
    attack_vector = "RESEARCH"
    cwe_ids = []
    published_date = item["published"][:10]
    tags = [item["query_used"]]
    raw = item
    return {
        "id": id,
        "title": title,
        "description": description,
        "source": source,
        "severity": severity,
        "cvss_score": cvss_score,
        "published_date": published_date,
        "attack_vector": attack_vector,
        "cwe_ids": cwe_ids,
        "tags": tags,
        "raw": raw
    }

def main():
    with open("data/raw/nvd_cves.json", "r") as f:
        nvd_cves = json.load(f)
    with open("data/raw/arxiv_papers.json", "r") as f:
        arxiv_papers = json.load(f)

    nvd_records = [extract_nvd_record(cve) for cve in nvd_cves]
    arxiv_records = [extract_arxiv_record(item) for item in arxiv_papers]

    total_nvd_records = len(nvd_records)
    total_arxiv_records = len(arxiv_records)

    all_records = nvd_records + arxiv_records
    deduplicated_records = [dict(t) for t in {tuple(d.items()) for d in all_records}]

    total_after_dedup = len(deduplicated_records)

    print(f"Total NVD records: {total_nvd_records}")
    print(f"Total ArXiv records: {total_arxiv_records}")
    print(f"Total after dedup: {total_after_dedup}")

    with open("data/processed/normalised.json", "w") as f:
        json.dump(deduplicated_records, f, indent=4)

if __name__ == "__main__":
    main()
