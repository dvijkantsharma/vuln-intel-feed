import subprocess
import sys

def main():
    steps = [
        "python pipeline/ingest/nvd_fetcher.py",
        "python pipeline/ingest/arxiv_fetcher.py",
        "python pipeline/ingest/normalise.py",
        "python pipeline/embed/embed_records.py",
        "python pipeline/cluster/cluster.py",
        "python pipeline/cluster/label_clusters.py",
        "python pipeline/output/write_sheets.py"
    ]

    for i, cmd in enumerate(steps, start=1):
        print(f"====== Step {i}: {cmd.split('/')[-1]} ======")
        result = subprocess.run(cmd, shell=True, check=False)
        if result.returncode != 0:
            print(f"FAILED at step {i}")
            sys.exit(1)

    print("Pipeline completed successfully.")

if __name__ == "__main__":
    main()
