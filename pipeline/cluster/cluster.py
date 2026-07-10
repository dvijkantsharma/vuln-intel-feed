import json
import numpy as np
import umap
import hdbscan
import pandas as pd
import sys

def main():
    embeddings = np.load("data/processed/embeddings.npy")
    ids = json.load(open("data/processed/embedding_ids.json"))
    metadatas = json.load(open("data/processed/embedding_metadatas.json"))
    documents = json.load(open("data/processed/embedding_documents.json"))

    if len(ids) < 10:
        print("Warning: fewer than 10 records")
        sys.exit(0)

    print(f"Loaded {len(ids)} embeddings with dimension {embeddings.shape[1]}")

    reducer = umap.UMAP(
        n_components=5,
        n_neighbors=30,
        min_dist=0.0,
        metric="cosine",
        random_state=42
    )
    reduced = reducer.fit_transform(embeddings)
    print(f"UMAP complete. Shape: {reduced.shape}")

    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=200,
        min_samples=10,
        metric="euclidean",
        cluster_selection_method="eom"
    )
    labels = clusterer.fit_predict(reduced)
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = int((labels == -1).sum())
    print(f"Found {n_clusters} clusters. Noise points: {n_noise}")

    rows = []
    for i in range(len(ids)):
        meta = metadatas[i]
        rows.append({
            "id":             ids[i],
            "cluster":        int(labels[i]),
            "title":          meta.get("title", ""),
            "source":         meta.get("source", ""),
            "severity":       meta.get("severity", ""),
            "cvss_score":     float(meta.get("cvss_score") or 0.0),
            "attack_vector":  meta.get("attack_vector", ""),
            "cwe_ids":        meta.get("cwe_ids", ""),
            "published_date": meta.get("published_date", ""),
            "description":    documents[i][:500]
        })

    df = pd.DataFrame(rows)
    df.to_json("data/processed/clustered.json", orient="records", indent=2)
    print(df["cluster"].value_counts().sort_index())

if __name__ == "__main__":
    main()
