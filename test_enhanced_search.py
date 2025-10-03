#!/usr/bin/env python3
"""
Test script for the enhanced UFDR search system
"""
import queryEngine
import json
import os

def test_search_system():
    print("🔍 Testing Enhanced UFDR Search System")
    print("=" * 50)
    
    # Test queries
    test_queries = [
        "fraud",
        "cybercrime", 
        "homicide",
        "UFDR-2024",
        "financial crimes",
        "New York",
        "evidence",
        "suspect",
        "investigation"
    ]
    
    for query in test_queries:
        print(f"\n🔎 Query: '{query}'")
        try:
            result = queryEngine.query(query, None)
            print(f"   ✅ Found {len(result['sources'])} results")
            
            if result['sources']:
                print(f"   📄 First result: {result['sources'][0]['title']}")
                print(f"   📅 Date: {result['sources'][0]['date']}")
                print(f"   🏷️  Type: {result['sources'][0]['type']}")
            
            if result['gps']:
                print(f"   🗺️  GPS points: {len(result['gps'])}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("✅ Search system test completed!")
    
    # Check available files
    print("\n📁 Available JSON files:")
    json_files = []
    
    # Check hardcoded files
    hardcoded_files = ["ufdr_report_1.json", "ufdr_report_2.json", "ufdr_report_3.json"]
    for filename in hardcoded_files:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"   📄 {filename} ({size:,} bytes)")
            json_files.append(filename)
    
    # Check uploaded files
    uploads_dir = "uploads"
    if os.path.exists(uploads_dir):
        for filename in os.listdir(uploads_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(uploads_dir, filename)
                size = os.path.getsize(filepath)
                print(f"   📤 {filename} ({size:,} bytes)")
                json_files.append(filepath)
    
    print(f"\n📊 Total files available for search: {len(json_files)}")

if __name__ == "__main__":
    test_search_system()
