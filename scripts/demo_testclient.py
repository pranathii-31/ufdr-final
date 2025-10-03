from fastapi.testclient import TestClient
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import main
import json

client = TestClient(main.app)

# Read files and upload via TestClient
files = []
for name in ['ufdr_report_1.json','ufdr_report_2.json','ufdr_report_3.json']:
    with open(name,'rb') as fh:
        files.append(('files',(name, fh.read(), 'application/json')))

print('POST /upload')
r = client.post('/upload', files=files)
print(r.status_code)
try:
    print(json.dumps(r.json(), indent=2))
except Exception:
    print(r.text)

print('POST /build_index')
r2 = client.post('/build_index')
print(r2.status_code)
try:
    print(r2.json())
except Exception:
    print(r2.text)

print('POST /query')
r3 = client.post('/query', json={'query':'Confirm the drop','language':'en'})
print(r3.status_code)
try:
    print(json.dumps(r3.json(), indent=2))
except Exception:
    print(r3.text)

print('GET /analytics')
r4 = client.get('/analytics')
print(r4.status_code)
try:
    print(json.dumps(r4.json(), indent=2))
except Exception:
    print(r4.text)

# Save last_query
try:
    with open('last_query.json','w',encoding='utf-8') as fh:
        json.dump(r3.json(), fh, indent=2, ensure_ascii=False)
    print('Saved last_query.json')
except Exception as e:
    print('Failed to write last_query.json', e)
