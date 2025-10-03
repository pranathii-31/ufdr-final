import sys
import os
import json

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, repo_root)

from fastapi.testclient import TestClient
import main


def run():
    client = TestClient(main.app)

    # list files
    r = client.get('/files')
    print('/files', r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)

    # analytics
    r = client.get('/analytics')
    print('/analytics', r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)

    # read last_query.json
    jq = os.path.join(repo_root, 'last_query.json')
    if not os.path.exists(jq):
        print('last_query.json not found')
        return
    with open(jq, 'r', encoding='utf-8') as fh:
        data = json.load(fh)

    session_id = data.get('session_id')
    if not session_id:
        print('No session_id in last_query.json')
        return

    # download PDF
    r = client.get(f'/export-pdf/{session_id}')
    if r.status_code == 200:
        pdf_path = os.path.join(repo_root, f'session_{session_id}.pdf')
        with open(pdf_path, 'wb') as fh:
            fh.write(r.content)
        print('Saved PDF to', pdf_path)
    else:
        print('Export PDF failed', r.status_code)

    # download TTS
    r = client.get(f'/tts/{session_id}')
    if r.status_code == 200:
        mp3_path = os.path.join(repo_root, f'session_{session_id}.mp3')
        with open(mp3_path, 'wb') as fh:
            fh.write(r.content)
        print('Saved MP3 to', mp3_path)
    else:
        print('TTS request failed', r.status_code)

    # chat history
    r = client.get(f'/chat-history/{session_id}')
    print('/chat-history', r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)


if __name__ == '__main__':
    run()
