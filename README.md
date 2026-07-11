# Vuln Intel Feed

An automated vulnerability intelligence pipeline that ingests CVEs from NVD and security research papers from ArXiv daily, clusters them semantically by attack vector, labels each cluster using an LLM with MITRE ATT&CK tactics, and outputs a structured report to Google Sheets.

Built entirely with free tools. Zero cloud spend.

---

## What It Does

1. **Ingests** CVE data from the NVD REST API v2.0 and security papers from ArXiv daily
2. **Normalises** both sources into a unified schema with severity, CVSS score, attack vector, and CWE IDs
3. **Embeds** each record using `nomic-embed-text` via Ollama running locally
4. **Clusters** records semantically using UMAP dimensionality reduction + HDBSCAN density clustering
5. **Labels** each cluster using Llama 3.3 70B, mapping to MITRE ATT&CK tactics
6. **Outputs** a three-tab Google Sheet: cluster summary, all records, and high severity filter (CVSS ≥ 7.0)

---

## Sample Output

| Cluster | Label | MITRE Tactic | Records |
|---|---|---|---|
| 0 | Oracle Product Vulnerabilities | Initial Access | 186 |
| 1 | Google Chrome Vulnerabilities | Initial Access | 637 |
| 2 | Linux Kernel Vulnerabilities | Privilege Escalation | 541 |
| 3 | WordPress Plugin Vulnerabilities | Privilege Escalation | 554 |
| 4 | Cross Site Scripting Vulnerabilities | Initial Access | 170 |
| 6 | Artificial Intelligence Research | Discovery | 130 |
| 8 | SQL Injection Vulnerabilities | Credential Access | 268 |
| 10 | Remote Code Execution Vulnerabilities | Execution | 455 |
| 11 | Deserialization and Memory Attacks | Impact | 3386 |

8,558 total records processed across 12 clusters.

---

## Architecture

```
NVD API ──────────────────────┐
                               ├──► Normalise ──► Embed (Ollama) ──► UMAP + HDBSCAN ──► LLM Label ──► Google Sheets
ArXiv API ────────────────────┘
```

```
vuln-intel-feed/
├── pipeline/
│   ├── ingest/
│   │   ├── nvd_fetcher.py       # Pulls CVEs from NVD API v2.0
│   │   ├── arxiv_fetcher.py     # Pulls security papers from ArXiv
│   │   └── normalise.py         # Merges sources into unified schema
│   ├── embed/
│   │   ├── chroma_setup.py      # Stub (numpy storage used instead)
│   │   └── embed_records.py     # Embeds records via Ollama nomic-embed-text
│   ├── cluster/
│   │   ├── cluster.py           # UMAP + HDBSCAN clustering
│   │   └── label_clusters.py    # LLM cluster labelling via Groq
│   └── output/
│       └── write_sheets.py      # Writes results to Google Sheets
├── data/
│   ├── raw/                     # Raw JSON from NVD and ArXiv (gitignored)
│   └── processed/               # Normalised, embedded, clustered data (gitignored)
├── n8n/
│   └── docker-compose.yml       # n8n scheduler for daily runs
├── run_pipeline.py              # Master runner — executes all 7 steps
├── requirements.txt
└── .env                         # API keys (gitignored)
```

---

## Tech Stack

| Layer | Tool | Cost |
|---|---|---|
| CVE data | NVD REST API v2.0 | Free |
| Research papers | ArXiv API | Free |
| Embeddings | Ollama + nomic-embed-text (local) | Free |
| Dimensionality reduction | UMAP | Free |
| Clustering | HDBSCAN | Free |
| LLM labelling | Groq API — Llama 3.3 70B | Free tier |
| Output | Google Sheets API | Free |
| Scheduling | n8n (self-hosted via Docker) | Free |

**Total infrastructure cost: $0/month**

---

## Setup

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.com) installed and running
- [Docker Desktop](https://www.docker.com/products/docker-desktop) (for n8n scheduling)
- Free API keys: [NVD](https://nvd.nist.gov/developers/request-an-api-key), [Groq](https://console.groq.com), [Google Cloud](https://console.cloud.google.com)

### 1. Clone and set up environment

```bash
git clone https://github.com/dvijkantsharma/vuln-intel-feed.git
cd vuln-intel-feed
python -m venv .venv
source .venv/Scripts/activate   # Windows
# source .venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
```

### 2. Pull the embedding model

```bash
ollama pull nomic-embed-text
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```
NVD_API_KEY=your_nvd_key
GROQ_API_KEY=your_groq_key
GOOGLE_SHEETS_ID=your_sheet_id
```

### 4. Set up Google Sheets

1. Create a Google Cloud project and enable the Sheets and Drive APIs
2. Create a service account, download credentials as `gcp_credentials.json`
3. Share your Google Sheet with the service account email as Editor
4. Add the Sheet ID to `.env`

### 5. Run the pipeline

```bash
python run_pipeline.py
```

This runs all 7 steps in sequence and updates your Google Sheet.

---

## Pipeline Steps

| Step | Script | Description |
|---|---|---|
| 1 | `nvd_fetcher.py` | Fetches CVEs published in the last 30 days from NVD |
| 2 | `arxiv_fetcher.py` | Fetches security papers across 6 search queries |
| 3 | `normalise.py` | Merges and deduplicates into unified schema |
| 4 | `embed_records.py` | Generates 768-dim embeddings, incremental (skips existing) |
| 5 | `cluster.py` | UMAP to 5D → HDBSCAN clustering |
| 6 | `label_clusters.py` | LLM labels each cluster with name + MITRE ATT&CK tactic |
| 7 | `write_sheets.py` | Writes 3-tab output to Google Sheets |

---

## Scheduling with n8n

```bash
cd n8n
docker compose up -d
```

Open http://localhost:5678 → create a Schedule Trigger workflow → Execute Command: `python /app/run_pipeline.py` → activate.

The pipeline will run daily at your configured time and refresh the Google Sheet automatically.

---

## Google Sheets Output

**Tab 1 — Cluster Summary**
One row per cluster with label, MITRE tactic, record count, average CVSS score, and source breakdown.

**Tab 2 — All Records**
Every CVE and paper with cluster label, MITRE tactic, severity, CVSS score, attack vector, CWE IDs, and description.

**Tab 3 — High Severity**
Filtered to CVSS ≥ 7.0, sorted descending. Actionable view for SOC or security team use.

---

## Key Design Decisions

**No vector database:** ChromaDB has irreconcilable onnxruntime DLL conflicts on Windows. Embeddings are stored as numpy arrays + JSON files — same functionality, zero dependency issues.

**HDBSCAN over k-means:** Discovers clusters automatically without specifying count in advance. Handles varying cluster densities and explicitly marks outliers as noise rather than forcing them into a cluster.

**Incremental embedding:** Records already embedded are skipped on subsequent runs. Only new CVEs from each daily fetch are embedded, keeping Step 4 fast after the initial run.

**Groq for LLM labelling:** NVIDIA NIM's free tier has availability fluctuations. Groq's free tier provides Llama 3.3 70B with consistent uptime for automated runs.

---

## Potential V2 Improvements

- MITRE ATT&CK technique-level mapping (T-codes, not just tactics)
- ExploitDB cross-reference to flag CVEs with known working exploits
- Streamlit dashboard with cluster timeline and trend visualisation
- RAG layer — query across all fetched papers via natural language
- Android/mobile CVE filter for mobile security focus

---

## Author

Dvij Kant Sharma
MSc Cybersecurity — University of Sydney
[LinkedIn](https://linkedin.com/in/yourprofile) · [GitHub](https://github.com/yourusername)
