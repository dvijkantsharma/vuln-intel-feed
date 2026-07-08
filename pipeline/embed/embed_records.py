import json
import sys
import importlib
from tqdm import tqdm
import ollama

# Add pipeline.embed to sys.path
sys.path.insert(0, 'pipeline/embed')

# Import get_collection from chroma_setup
chroma_setup = importlib.import_module('chroma_setup')
get_collection = chroma_setup.get_collection

# Load data
with open('data/processed/normalised.json') as f:
    records = json.load(f)

# Slice records for testing
records = records[:10]

# Get collection and client
collection, client = get_collection()

# Get existing IDs
existing_ids = collection.get()["ids"]

# Initialize progress bar
pbar = tqdm(total=len(records))

# Embed records in batches
for i in range(0, len(records), 50):
    batch = records[i:i+50]
    batch_ids = [record["id"] for record in batch]
    
    # Skip records already embedded
    new_batch_ids = [id for id in batch_ids if id not in existing_ids]
    new_batch = [record for record in batch if record["id"] in new_batch_ids]
    
    if new_batch:
        # Build embedding text
        embedding_texts = []
        for record in new_batch:
            text = record["title"] + " " + record["description"] + " " + " ".join(record["cwe_ids"]) + " " + record["attack_vector"]
            text = text[:2000]  # Trim to 2000 characters max
            embedding_texts.append(text)
        
        embeddings = []
        for text in embedding_texts:
            result = ollama.embeddings(model="nomic-embed-text", prompt=text)
            embeddings.append(result["embedding"])
        
        # Store embeddings in ChromaDB
        for j, record in enumerate(new_batch):
            metadata = {
                "source": record["source"],
                "severity": record.get("severity", ""),
                "cvss_score": record.get("cvss_score", 0.0),
                "published_date": record["published_date"],
                "attack_vector": record["attack_vector"],
                "cwe_ids": ",".join(record["cwe_ids"]),
                "title": record["title"][:200]
            }
            collection.add(
                embeddings=[embeddings[j]],
                metadatas=[metadata],
                ids=[record["id"]]
            )
    
    # Update progress bar
    pbar.update(len(batch))

# Print final ChromaDB record count
print(collection.get()["ids"])

# Close progress bar
pbar.close()
