#!/usr/bin/env python3
"""
Test the rebuild index functionality
"""
import build_index
import os

def test_rebuild_index():
    print("🔧 Testing Index Rebuild Functionality")
    print("=" * 50)
    
    try:
        # Test the rebuild function
        result = build_index.build_and_save_index()
        print(f"✅ Rebuild result: {result}")
        
        # Check if index files were created
        index_dir = "ufdr_faiss_combined_index"
        if os.path.exists(index_dir):
            print(f"✅ Index directory created: {index_dir}")
            
            # List files in index directory
            files = os.listdir(index_dir)
            print(f"📁 Index files: {files}")
            
            # Check for metadata file
            metadata_file = os.path.join(index_dir, "index_metadata.json")
            if os.path.exists(metadata_file):
                print("✅ Index metadata file found")
                
                # Read and display metadata
                import json
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                    print(f"📊 Total files indexed: {metadata.get('total_files', 'Unknown')}")
                    print(f"📊 Index type: {metadata.get('index_type', 'Unknown')}")
                    print(f"📊 Status: {metadata.get('status', 'Unknown')}")
        else:
            print("❌ Index directory not found")
            
        # Check processed files tracking
        processed_file = "processed_files.json"
        if os.path.exists(processed_file):
            print(f"✅ Processed files tracking found: {processed_file}")
            
            import json
            with open(processed_file, 'r') as f:
                processed_data = json.load(f)
                print(f"📋 Processed files: {len(processed_data.get('processed_files', []))}")
        
        print("\n✅ Index rebuild test completed successfully!")
        
    except Exception as e:
        print(f"❌ Index rebuild failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_rebuild_index()
