import json
import os
import numpy as np
import ollama
import tqdm
import pathlib

# Load data
with open('data/processed/normalised.json') as f:
    records = json.load(f)



# Load existing IDs
try:
    with open('data/processed/embedding_ids.json') as f:
        existing_ids = json.load(f)
except FileNotFoundError:
    existing_ids = []

# Initialize progress bar
pbar = tqdm.tqdm(total=len(records))

# Embed records
all_embeddings = []
all_ids = existing_ids[:]
all_metadatas = []
all_documents = []
for record in records:
    if record["id"] not in existing_ids:
        # Build embedding text
        embedding_text = record["title"] + " " + record["description"] + " " + " ".join(record["cwe_ids"]) + " " + record["attack_vector"]
        embedding_text = embedding_text[:2000]  # Trim to 2000 characters max
        
        # Get embedding
        result = ollama.embeddings(model="nomic-embed-text", prompt=embedding_text)
        embedding = result["embedding"]
        
        # Store embedding and metadata
        all_embeddings.append(embedding)
        all_ids.append(record["id"])
        metadata = {
            "source":         record.get("source") or "",
            "severity":       record.get("severity") or "",
            "cvss_score":     float(record.get("cvss_score") or 0.0),
            "published_date": record.get("published_date") or "",
            "attack_vector":  record.get("attack_vector") or "",
            "cwe_ids":        ",".join(record.get("cwe_ids") or []),
            "title":          (record.get("title") or "")[:200]
        }
        all_metadatas.append(metadata)
        all_documents.append(embedding_text)
    
    # Update progress bar
    pbar.update(1)

# Load existing embeddings
try:
    existing_embeddings = np.load('data/processed/embeddings.npy')
    all_embeddings = list(existing_embeddings) + all_embeddings
except FileNotFoundError:
    pass

# Save everything
np.save("data/processed/embeddings.npy", np.array(all_embeddings))
with open('data/processed/embedding_ids.json', 'w') as f:
    json.dump(all_ids, f)
with open('data/processed/embedding_metadatas.json', 'w') as f:
    json.dump(all_metadatas, f)
with open('data/processed/embedding_documents.json', 'w') as f:
    json.dump(all_documents, f)

# Print final count
print(len(all_ids))
