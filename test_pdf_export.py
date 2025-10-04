"""
Test PDF Export Functionality
"""

import requests
import json

def test_pdf_export():
    """Test the PDF export endpoint"""
    print("🧪 Testing PDF Export Functionality")
    print("=" * 40)
    
    # Test data
    test_chat_history = [
        {
            "type": "user",
            "text": "Hello, can you help me with a search query?",
            "results": []
        },
        {
            "type": "assistant", 
            "text": "Of course! I'd be happy to help you with your search query. What would you like to search for?",
            "results": [{"source": "test_document.pdf", "content": "Sample content"}]
        },
        {
            "type": "user",
            "text": "I'm looking for information about financial fraud cases.",
            "results": []
        },
        {
            "type": "assistant",
            "text": "I found several relevant documents about financial fraud cases. Here are the key findings...",
            "results": [
                {"source": "fraud_case_1.pdf", "content": "Case details"},
                {"source": "fraud_case_2.pdf", "content": "Evidence files"}
            ]
        }
    ]
    
    try:
        # Test the PDF export endpoint
        url = "http://localhost:8000/export-pdf"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token"  # This will fail auth, but we can see the error
        }
        data = {
            "chat_history": test_chat_history
        }
        
        print("1. Testing PDF export endpoint...")
        response = requests.post(url, headers=headers, json=data, timeout=10)
        
        print(f"   Status Code: {response.status_code}")
        print(f"   Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            print("   ✅ PDF export successful!")
            print(f"   Content-Type: {response.headers.get('content-type')}")
            print(f"   Content-Length: {response.headers.get('content-length')}")
            
            # Save the PDF for inspection
            with open("test_export.pdf", "wb") as f:
                f.write(response.content)
            print("   📄 PDF saved as 'test_export.pdf'")
            
        elif response.status_code == 401:
            print("   ⚠️  Authentication required (expected)")
            print("   Response:", response.text[:200])
            
        else:
            print(f"   ❌ PDF export failed with status {response.status_code}")
            print("   Response:", response.text[:200])
            
    except requests.exceptions.ConnectionError:
        print("   ❌ Could not connect to server. Is it running?")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n2. Testing server health...")
    try:
        health_response = requests.get("http://localhost:8000/health", timeout=5)
        print(f"   Health check: {health_response.status_code}")
    except:
        print("   ❌ Server not responding")

if __name__ == "__main__":
    test_pdf_export()
