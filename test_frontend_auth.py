"""
Test Frontend Authentication and Audit Logs Access
"""

import requests
import json

def test_frontend_auth_flow():
    """Test the complete authentication flow that the frontend uses"""
    print("🔐 Testing Frontend Authentication Flow")
    print("=" * 50)
    
    base_url = "http://127.0.0.1:8000"
    
    # Step 1: Create a test user
    print("1. Creating test user...")
    try:
        signup_response = requests.post(
            f"{base_url}/signup",
            json={
                "name": "Frontend Test User",
                "email": "frontend@test.com", 
                "password": "testpass123"
            }
        )
        print(f"   Signup status: {signup_response.status_code}")
        if signup_response.status_code == 200:
            print("   ✅ User created successfully")
        elif signup_response.status_code == 400 and "already registered" in signup_response.text:
            print("   ⚠️  User already exists (continuing with login)")
        else:
            print(f"   ❌ Signup failed: {signup_response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Signup error: {e}")
    
    # Step 2: Login
    print("\n2. Logging in...")
    try:
        login_response = requests.post(
            f"{base_url}/login",
            json={
                "email": "frontend@test.com",
                "password": "testpass123"
            }
        )
        print(f"   Login status: {login_response.status_code}")
        
        if login_response.status_code == 200:
            login_data = login_response.json()
            token = login_data.get('token')
            user_info = login_data.get('user', {})
            
            print(f"   ✅ Login successful")
            print(f"   📧 User: {user_info.get('email', 'N/A')}")
            print(f"   🔑 Token: {token[:20]}..." if token else "No token")
            
            # Step 3: Test audit logs access
            print("\n3. Testing audit logs access...")
            audit_response = requests.get(
                f"{base_url}/audit-logs",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
            )
            
            print(f"   Audit logs status: {audit_response.status_code}")
            print(f"   Content-Type: {audit_response.headers.get('content-type', 'N/A')}")
            
            if audit_response.status_code == 200:
                audit_data = audit_response.json()
                print(f"   ✅ Audit logs accessible")
                print(f"   📊 Total entries: {audit_data.get('total', 0)}")
                print(f"   📄 Items returned: {len(audit_data.get('items', []))}")
                
                # Show first few audit entries
                items = audit_data.get('items', [])
                if items:
                    print(f"   📋 Sample entries:")
                    for i, item in enumerate(items[:3]):
                        print(f"      {i+1}. {item.get('action', 'N/A')} by {item.get('user', 'N/A')}")
            else:
                print(f"   ❌ Audit logs failed: {audit_response.text[:200]}")
                
        else:
            print(f"   ❌ Login failed: {login_response.text[:200]}")
            
    except Exception as e:
        print(f"   ❌ Login error: {e}")
    
    # Step 4: Test without authentication (should fail)
    print("\n4. Testing audit logs without authentication...")
    try:
        no_auth_response = requests.get(f"{base_url}/audit-logs")
        print(f"   Status: {no_auth_response.status_code}")
        if no_auth_response.status_code == 401:
            print("   ✅ Correctly requires authentication")
        else:
            print(f"   ⚠️  Unexpected response: {no_auth_response.text[:100]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("🎉 Authentication flow test completed!")

if __name__ == "__main__":
    test_frontend_auth_flow()
