import chromadb

def get_collection(name="vuln_intel"):
    client = chromadb.PersistentClient(path="./chroma_db")
    from chromadb.api.types import EmbeddingFunction
    collection = client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
        embedding_function=None
    )
    return collection, client
