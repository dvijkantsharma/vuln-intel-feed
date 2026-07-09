import sys
import numpy as np
import pandas as pd
from sklearn.manifold import UMAP
from hdbscan import HDBSCAN
from pipeline.embed.chroma_setup import get_collection

def main():
    collection, client = get_collection()
    result = collection.get(include=["embeddings", "metadatas", "documents"])
    ids, embeddings, metadatas, documents = result["ids"], result["embeddings"], result["metadatas"], result["documents"]
    embeddings = np.array(embeddings)

    if len(embeddings) < 10:
        print("Warning: fewer than 10 records")
        sys.exit(0)

    umap_model = UMAP(n_components=5, n_neighbors=15, min_dist=0.1, metric="cosine", random_state=42)
    umap_embeddings = umap_model.fit_transform(embeddings)

    hdbscan_model = HDBSCAN(min_cluster_size=5, min_samples=3, metric="euclidean", cluster_selection_method="eom")
    clusters = hdbscan_model.fit_predict(umap_embeddings)

    num_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
    num_noise_points = sum(1 for cluster in clusters if cluster == -1)
    print(f"Number of clusters found: {num_clusters}")
    print(f"Number of noise points: {num_noise_points}")

    data = {
        "id": ids,
        "cluster": clusters,
        "title": [meta.get("title", "") for meta in metadatas],
        "source": [meta.get("source", "") for meta in metadatas],
        "severity": [meta.get("severity", "") for meta in metadatas],
        "cvss_score": [meta.get("cvss_score", 0.0) for meta in metadatas],
        "attack_vector": [meta.get("attack_vector", "") for meta in metadatas],
        "cwe_ids": [meta.get("cwe_ids", "") for meta in metadatas],
        "published_date": [meta.get("published_date", "") for meta in metadatas],
        "description": [doc[:500] for doc in documents]
    }
    df = pd.DataFrame(data)
    df.to_json("data/processed/clustered.json", orient="records", indent=2)
    print(df["cluster"].value_counts())

if __name__ == "__main__":
    main()
