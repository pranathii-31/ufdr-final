import sys
import os
import json

# Ensure repo root is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, repo_root)

from fastapi.testclient import TestClient

import main


def main_run():
    client = TestClient(main.app)

    base = repo_root
    filenames = [
        'ufdr_report_1.json',
        'ufdr_report_2.json',
        'ufdr_report_3.json',
    ]

    files = []
    opened = []
    for name in filenames:
        path = os.path.join(base, name)
        if os.path.exists(path):
            f = open(path, 'rb')
            opened.append(f)
            files.append(('files', (name, f, 'application/json')))
        else:
            print(f'Warning: {name} not found at {path}')

    if files:
        print('Uploading files:', [n for n in filenames if os.path.exists(os.path.join(base, n))])
        r = client.post('/upload', files=files)
        print('Upload status:', r.status_code)
        try:
            print('Upload response:', r.json())
        except Exception:
            print('Upload response text:', r.text)
    else:
        print('No files to upload; skipping upload')

    for f in opened:
        try:
            f.close()
        except Exception:
            pass

    # Trigger index rebuild (if endpoint exists)
    try:
        r = client.post('/build_index')
        print('/build_index', r.status_code)
        try:
            print(r.json())
        except Exception:
            print(r.text)
    except Exception as e:
        print('Error calling /build_index:', e)

    # Run a sample query
    query_payload = {'query': 'confirm the drop', 'language': 'en'}
    r = client.post('/query', json=query_payload)
    print('/query', r.status_code)
    if r.status_code == 200:
        resp = r.json()
        out_path = os.path.join(base, 'last_query.json')
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(resp, fh, ensure_ascii=False, indent=2)
        print('Saved query result to', out_path)
    else:
        try:
            print('Query error:', r.json())
        except Exception:
            print('Query response:', r.text)

    # Get analytics
    try:
        r = client.get('/analytics')
        print('/analytics', r.status_code, r.json())
    except Exception as e:
        print('Error getting analytics:', e)

    # Print recent audit logs from DB if available
    try:
        from database import SessionLocal
        from models import AuditLog

        db = SessionLocal()
        logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(10).all()
        print('Recent audit logs:')
        for l in logs:
            print(l.id, l.user, l.action, l.extra)
    except Exception as e:
        print('Could not read audit logs:', e)


if __name__ == '__main__':
    main_run()
