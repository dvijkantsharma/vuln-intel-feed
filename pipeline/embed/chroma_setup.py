import chromadb

def get_collection(name="vuln_intel"):
    client = chromadb.PersistentClient(path="./chroma_db")
    collection = client.get_or_create_collection(name)
    collection.set_metadata({"hnsw:space": "cosine"})
    return collection, client
