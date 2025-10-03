import requests
import time
import json

BASE = 'http://127.0.0.1:8000'

files_to_upload = [
    'ufdr_report_1.json',
    'ufdr_report_2.json',
    'ufdr_report_3.json',
]

# Upload files
files = []
for p in files_to_upload:
    files.append(('files', (p, open(p, 'rb'), 'application/json')))

print('Uploading files:', files_to_upload)
r = requests.post(f'{BASE}/upload', files=files)
print('/upload', r.status_code)
try:
    print(r.json())
except Exception:
    print(r.text)

# Trigger build index
print('Triggering /build_index')
r2 = requests.post(f'{BASE}/build_index')
print('/build_index', r2.status_code)
try:
    print(r2.json())
except Exception:
    print(r2.text)

# Wait briefly for index to finish
print('Waiting 3s for index work to settle...')
time.sleep(3)

# Run a sample query
payload = {'query': 'Confirm the drop', 'language': 'en'}
print('Running /query with:', payload)
r3 = requests.post(f'{BASE}/query', json=payload)
print('/query', r3.status_code)

try:
    data = r3.json()
    print('Query response keys:', list(data.keys()))
    # Save to last_query.json
    with open('last_query.json', 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print('Saved last_query.json')
except Exception:
    print(r3.text)

# Fetch analytics
r4 = requests.get(f'{BASE}/analytics')
print('/analytics', r4.status_code)
try:
    print(r4.json())
except Exception:
    print(r4.text)

print('Done')
