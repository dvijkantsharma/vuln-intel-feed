import requests
import xml.etree.ElementTree as ET
import json
import time

def fetch_arxiv_papers():
    queries = [
        "vulnerability detection",
        "CVE exploit",
        "adversarial machine learning security",
        "LLM jailbreak",
        "network intrusion detection",
        "fuzzing vulnerability",
    ]
    papers = {}
    for query in queries:
        url = f"http://export.arxiv.org/api/query?search_query={query}&max_results=20&sortBy=submittedDate&sortOrder=descending"
        response = requests.get(url)
        root = ET.fromstring(response.content)
        namespace = "{http://www.w3.org/2005/Atom}"
        for entry in root.findall(namespace + "entry"):
            id = entry.find(namespace + "id").text
            if id not in papers:
                title = entry.find(namespace + "title").text
                summary = entry.find(namespace + "summary").text
                published = entry.find(namespace + "published").text
                papers[id] = {
                    "id": id,
                    "title": title,
                    "summary": summary,
                    "published": published,
                    "source": "arxiv",
                    "query_used": query,
                }
        time.sleep(3)
    with open("data/raw/arxiv_papers.json", "w") as f:
        json.dump(list(papers.values()), f)
    print(f"Fetched {len(papers)} unique papers")

if __name__ == "__main__":
    fetch_arxiv_papers()
