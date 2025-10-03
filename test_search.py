import queryEngine
import json

# Test search functionality
test_queries = ["fraud", "cybercrime", "homicide", "UFDR-2024", "financial"]

print("Testing search functionality with updated JSON files...")
for query in test_queries:
    try:
        result = queryEngine.query(query, None)
        print(f"Query: '{query}' -> Found {len(result['sources'])} results")
        if result['sources']:
            print(f"  First result: {result['sources'][0]['title']}")
        if result['gps']:
            print(f"  GPS points: {len(result['gps'])}")
    except Exception as e:
        print(f"Query: '{query}' -> ERROR: {e}")

print("\nSearch functionality test completed!")
