import json
import os
import numpy as np
import ollama
import tqdm

with open("data/processed/normalised.json") as f:
    records = json.load(f)

# Load all existing data
try:
    existing_ids = json.load(open("data/processed/embedding_ids.json"))
except FileNotFoundError:
    existing_ids = []

try:
    existing_meta = json.load(open("data/processed/embedding_metadatas.json"))
except FileNotFoundError:
    existing_meta = []

try:
    existing_docs = json.load(open("data/processed/embedding_documents.json"))
except FileNotFoundError:
    existing_docs = []

try:
    existing_emb = list(np.load("data/processed/embeddings.npy"))
except FileNotFoundError:
    existing_emb = []

# Start from existing data
all_ids = existing_ids[:]
all_meta = existing_meta[:]
all_docs = existing_docs[:]
all_emb = existing_emb[:]

existing_id_set = set(existing_ids)

# Only embed new records
new_records = [r for r in records if r["id"] not in existing_id_set]
print(f"Total: {len(records)} | Already embedded: {len(existing_ids)} | New: {len(new_records)}")

for record in tqdm.tqdm(new_records):
    embedding_text = (
        (record.get("title") or "") + " " +
        (record.get("description") or "") + " " +
        " ".join(record.get("cwe_ids") or []) + " " +
        (record.get("attack_vector") or "")
    )[:2000]

    result = ollama.embeddings(model="nomic-embed-text", prompt=embedding_text)

    all_ids.append(record["id"])
    all_emb.append(result["embedding"])
    all_meta.append({
        "source":         record.get("source") or "",
        "severity":       record.get("severity") or "",
        "cvss_score":     float(record.get("cvss_score") or 0.0),
        "published_date": record.get("published_date") or "",
        "attack_vector":  record.get("attack_vector") or "",
        "cwe_ids":        ",".join(record.get("cwe_ids") or []),
        "title":          (record.get("title") or "")[:200]
    })
    all_docs.append(embedding_text)

# Save all four files atomically with same length
assert len(all_ids) == len(all_emb) == len(all_meta) == len(all_docs), \
    f"Length mismatch: ids={len(all_ids)}, emb={len(all_emb)}, meta={len(all_meta)}, docs={len(all_docs)}"

np.save("data/processed/embeddings.npy", np.array(all_emb))
json.dump(all_ids,  open("data/processed/embedding_ids.json", "w"))
json.dump(all_meta, open("data/processed/embedding_metadatas.json", "w"))
json.dump(all_docs, open("data/processed/embedding_documents.json", "w"))

print(f"Saved {len(all_ids)} total embeddings.")
