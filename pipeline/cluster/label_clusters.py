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

# Load data
df = pd.read_json('data/processed/clustered.json')

# Dry test
dry_test_records = [
    {"title": "Test Record 1", "description": "This is a test record"},
    {"title": "Test Record 2", "description": "This is another test record"}
]
dry_test_prompt = f"Label the following cluster of records: {json.dumps(dry_test_records)}\nReturn JSON with label, mitre_tactic, and description."
dry_test_response = {"label": "Test Label", "mitre_tactic": "Initial Access", "description": "This is a test description"}
dry_test_json = json.dumps(dry_test_response)
try:
    json.loads(dry_test_json)
    print("DRY RUN PASSED")
except json.JSONDecodeError:
    print("DRY RUN FAILED")

# Label clusters
cluster_labels = {}
for cluster_id in df['cluster'].unique():
    if cluster_id == -1:
        continue
    cluster_records = df[df['cluster'] == cluster_id].sample(min(5, len(df[df['cluster'] == cluster_id])))
    prompt = f"Label the following cluster of records: {json.dumps(cluster_records.to_dict(orient='records'))}\nReturn JSON with label, mitre_tactic, and description."
    response = client.chat.completions.create(
        model=MODEL,
        prompt=prompt,
        temperature=0.2,
        max_tokens=300
    )
    response_text = response['choices'][0]['text']
    # Strip markdown fences and text before and after JSON
    if response_text.startswith('```'):
        response_text = response_text.split('```', 1)[1]
    response_text = response_text.split('{', 1)[1].rsplit('}', 1)[0] + '}'
    try:
        response_json = json.loads(response_text)
    except json.JSONDecodeError:
        response_json = {"label": "Uncategorised", "mitre_tactic": "Unknown", "description": "Parse error"}
    cluster_labels[cluster_id] = {
        "label": response_json["label"],
        "mitre_tactic": response_json["mitre_tactic"],
        "description": response_json["description"],
        "record_count": len(df[df['cluster'] == cluster_id]),
        "avg_cvss": df[df['cluster'] == cluster_id]['cvss'].mean(),
        "sources": df[df['cluster'] == cluster_id]['source'].unique().tolist()
    }
    time.sleep(1.5)

# Add cluster labels to DataFrame
df['cluster_label'] = df['cluster'].apply(lambda x: cluster_labels.get(x, {"label": "Noise"})["label"] if x != -1 else "Noise")
df['cluster_mitre_tactic'] = df['cluster'].apply(lambda x: cluster_labels.get(x, {"mitre_tactic": ""})["mitre_tactic"] if x != -1 else "")

# Save labelled clusters
df.to_json('data/processed/labelled_clusters.json', orient='records', indent=2)

# Save cluster summary
with open('data/processed/cluster_summary.json', 'w') as f:
    json.dump(cluster_labels, f, indent=2)

# Print cluster labels
for cluster_id, label in cluster_labels.items():
    print(f"Cluster {cluster_id}: [{label['mitre_tactic']}] {label['label']}")
