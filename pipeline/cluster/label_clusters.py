from openai import OpenAI
from dotenv import load_dotenv
import os
import pandas as pd
import json
import time

load_dotenv()

client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=os.getenv("NVIDIA_API_KEY")
)
MODEL = "meta/llama-3.3-70b-instruct"

df = pd.read_json("data/processed/clustered.json")

# Dry run to verify JSON parsing
dry_test_json = '{"label": "Test", "mitre_tactic": "Initial Access", "description": "Test desc"}'
try:
    json.loads(dry_test_json)
    print("DRY RUN PASSED")
except json.JSONDecodeError:
    print("DRY RUN FAILED")
    exit(1)

cluster_labels = {}

for cluster_id in sorted([c for c in df["cluster"].unique() if c != -1]):
    cluster_df = df[df["cluster"] == cluster_id]
    sample = cluster_df.sample(min(5, len(cluster_df)))

    prompt = f"""You are a senior cybersecurity analyst. These {len(sample)} records belong to the same vulnerability cluster.

{json.dumps(sample[["title", "description", "attack_vector", "cwe_ids"]].to_dict(orient="records"), indent=2)}

Return ONLY valid JSON, no preamble, no markdown:
{{"label": "4-8 word cluster name", "mitre_tactic": "one of: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact", "description": "2 sentence summary"}}"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=300
        )
        content = response.choices[0].message.content.strip()

        # Strip markdown fences
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1])

        # Extract JSON object
        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            content = content[start:end]

        result = json.loads(content)

    except Exception as e:
        print(f"  Error on cluster {cluster_id}: {e}")
        result = {"label": "Uncategorised", "mitre_tactic": "Unknown", "description": "Parse error"}

    cluster_labels[int(cluster_id)] = {
        "label":        result.get("label", "Uncategorised"),
        "mitre_tactic": result.get("mitre_tactic", "Unknown"),
        "description":  result.get("description", ""),
        "record_count": len(cluster_df),
        "avg_cvss":     round(float(cluster_df["cvss_score"].mean()), 2),
        "sources":      cluster_df["source"].value_counts().to_dict()
    }

    print(f"Cluster {cluster_id}: [{result.get('mitre_tactic','?')}] {result.get('label','?')}")
    time.sleep(1.5)

df["cluster_label"] = df["cluster"].map(
    lambda x: cluster_labels.get(int(x), {}).get("label", "Noise") if x != -1 else "Noise"
)
df["cluster_mitre_tactic"] = df["cluster"].map(
    lambda x: cluster_labels.get(int(x), {}).get("mitre_tactic", "") if x != -1 else ""
)

df.to_json("data/processed/labelled_clusters.json", orient="records", indent=2)

with open("data/processed/cluster_summary.json", "w") as f:
    json.dump(cluster_labels, f, indent=2)

print("\nDone.")
