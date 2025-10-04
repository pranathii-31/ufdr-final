"""
Test Collaboration Functionality
"""

import requests
import json

def test_collaboration_endpoints():
    """Test the collaboration and sharing endpoints"""
    print("🤝 Testing Collaboration Functionality")
    print("=" * 50)
    
    base_url = "http://localhost:8000"
    
    # Test data
    test_share_data = {
        "type": "search_results",
        "query": "contacts with yahoo emails",
        "results": [
            {"name": "John Doe", "email": "john@yahoo.com", "phone": "+1234567890"},
            {"name": "Jane Smith", "email": "jane@yahoo.com", "phone": "+0987654321"}
        ],
        "conversation": [
            {"type": "user", "text": "contacts with yahoo emails"},
            {"type": "assistant", "text": "I found 2 contacts with Yahoo emails..."}
        ],
        "timestamp": "2025-10-04T12:00:00Z",
        "user": "test@forenseek.com",
        "metadata": {
            "total_results": 2,
            "conversation_length": 2,
            "search_type": "forensic_analysis"
        }
    }
    
    # Test 1: Generate Share Link
    print("1. Testing Share Link Generation...")
    try:
        response = requests.post(
            f"{base_url}/api/share/generate-link",
            headers={"Content-Type": "application/json"},
            json={
                "data": test_share_data,
                "permissions": "view",
                "expiry_days": 7,
                "message": "Test share for forensic analysis"
            }
        )
        
        if response.status_code == 401:
            print("   ⚠️  Authentication required (expected)")
        elif response.status_code == 200:
            data = response.json()
            print(f"   ✅ Share link generated: {data.get('link', 'N/A')}")
            print(f"   📋 Share ID: {data.get('share_id', 'N/A')}")
            print(f"   ⏰ Expires: {data.get('expires_at', 'N/A')}")
        else:
            print(f"   ❌ Failed with status {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            
    except requests.exceptions.ConnectionError:
        print("   ❌ Could not connect to server. Is it running?")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 2: Email Share
    print("\n2. Testing Email Share...")
    try:
        response = requests.post(
            f"{base_url}/api/share/send-email",
            headers={"Content-Type": "application/json"},
            json={
                "data": test_share_data,
                "recipients": ["colleague1@example.com", "colleague2@example.com"],
                "message": "Please review these forensic findings",
                "permissions": "comment"
            }
        )
        
        if response.status_code == 401:
            print("   ⚠️  Authentication required (expected)")
        elif response.status_code == 200:
            data = response.json()
            print(f"   ✅ Email share sent: {data.get('message', 'N/A')}")
            print(f"   📧 Recipients sent: {data.get('recipients_sent', 0)}")
        else:
            print(f"   ❌ Failed with status {response.status_code}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 3: Export Generation
    print("\n3. Testing Export Generation...")
    try:
        response = requests.post(
            f"{base_url}/api/share/generate-export",
            headers={"Content-Type": "application/json"},
            json={
                "data": test_share_data,
                "format": "pdf",
                "include_metadata": True
            }
        )
        
        if response.status_code == 401:
            print("   ⚠️  Authentication required (expected)")
        elif response.status_code == 200:
            print(f"   ✅ Export generated successfully")
            print(f"   📄 Content-Type: {response.headers.get('content-type', 'N/A')}")
            print(f"   📊 Content-Length: {response.headers.get('content-length', 'N/A')}")
            
            # Save the export for inspection
            with open("test_collaboration_export.pdf", "wb") as f:
                f.write(response.content)
            print("   💾 Export saved as 'test_collaboration_export.pdf'")
        else:
            print(f"   ❌ Failed with status {response.status_code}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 4: Server Health
    print("\n4. Testing Server Health...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        print(f"   Health check: {response.status_code}")
    except:
        print("   ❌ Server not responding")
    
    print("\n" + "=" * 50)
    print("🎉 Collaboration functionality test completed!")

if __name__ == "__main__":
    test_collaboration_endpoints()
