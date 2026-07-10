import os
import json
import pandas as pd
from google.oauth2.service_account import Credentials
import gspread
from gspread.exceptions import WorksheetNotFound
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Load credentials and authenticate
creds = Credentials.from_service_account_file(
    'gcp_credentials.json',
    scopes=['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
)
client = gspread.authorize(creds)

# Open spreadsheet by key
spreadsheet = client.open_by_key(os.getenv('GOOGLE_SHEETS_ID'))

# Load data
labelled_clusters_df = pd.read_json('data/processed/labelled_clusters.json')
cluster_summary_dict = json.load(open('data/processed/cluster_summary.json'))

# Create or clear worksheet tabs
try:
    ws1 = spreadsheet.worksheet('Cluster Summary')
except WorksheetNotFound:
    ws1 = spreadsheet.add_worksheet('Cluster Summary', rows=100, cols=20)

try:
    ws2 = spreadsheet.worksheet('All Records')
except WorksheetNotFound:
    ws2 = spreadsheet.add_worksheet('All Records', rows=1000, cols=20)

try:
    ws3 = spreadsheet.worksheet('High Severity')
except WorksheetNotFound:
    ws3 = spreadsheet.add_worksheet('High Severity', rows=1000, cols=20)

# Write data to worksheets
ws1.clear()
ws1.update([['Cluster ID', 'Label', 'MITRE Tactic', 'Record Count', 'Avg CVSS', 'NVD Count', 'ArXiv Count']], 'A1')
ws1.update(labelled_clusters_df.fillna('').values.tolist(), 'A2')

ws2.clear()
ws2.update([['id', 'title', 'source', 'cluster_label', 'cluster_mitre_tactic', 'severity', 'cvss_score', 'attack_vector', 'cwe_ids', 'published_date', 'description']], 'A1')
ws2.update(labelled_clusters_df.fillna('').values.tolist(), 'A2')

high_severity_df = labelled_clusters_df[labelled_clusters_df['cvss_score'] >= 7.0].sort_values(by='cvss_score', ascending=False)
ws3.clear()
ws3.update([['id', 'title', 'source', 'cluster_label', 'cluster_mitre_tactic', 'severity', 'cvss_score', 'attack_vector', 'cwe_ids', 'published_date', 'description']], 'A1')
ws3.update(high_severity_df.fillna('').values.tolist(), 'A2')

# Print row counts
print(f'Cluster Summary: {len(labelled_clusters_df)} rows')
print(f'All Records: {len(labelled_clusters_df)} rows')
print(f'High Severity: {len(high_severity_df)} rows')
