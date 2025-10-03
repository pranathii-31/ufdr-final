from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain.schema import Document
from langchain_community.embeddings import HuggingFaceEmbeddings
import os
import json
import time
from typing import List, Optional
import shutil

HARDCODED_FILES = ["ufdr_report_1.json", "ufdr_report_2.json", "ufdr_report_3.json"]
FAISS_INDEX_DIR = "ufdr_faiss_index"

def load_json_text(path: str) -> dict:
    """Load and parse a JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def ensure_index_exists():
    """Ensure the FAISS index exists, create it from hardcoded files if not."""
    if not os.path.exists(FAISS_INDEX_DIR) or not os.listdir(FAISS_INDEX_DIR):
        build_index_from_hardcoded_files()

def build_index_from_hardcoded_files():
    """Build FAISS index from only the hardcoded files."""
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_community.vectorstores import FAISS
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain.schema import Document

    print("Building index from hardcoded files...")
    documents = []
    
    # Process only hardcoded files
    for filename in HARDCODED_FILES:
        if not os.path.exists(filename):
            print(f"Warning: {filename} not found, skipping...")
            continue
        
        json_data = load_json_text(filename)
        doc = Document(
            page_content=json.dumps(json_data, separators=(',', ':')),
            metadata={"source": filename}
        )
        documents.append(doc)
    
    if not documents:
        raise Exception("No hardcoded files found to process")

    # Create chunks
    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=100)
    docs = splitter.split_documents(documents)

    # Create and save index
    embedding_model = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )
    vectorstore = FAISS.from_documents(docs, embedding_model)
    
    # Ensure directory exists and is empty
    if os.path.exists(FAISS_INDEX_DIR):
        shutil.rmtree(FAISS_INDEX_DIR)
    os.makedirs(FAISS_INDEX_DIR)
    
    vectorstore.save_local(FAISS_INDEX_DIR)
    print("✅ FAISS index built and saved from hardcoded files!")


def extract_metadata(json_data: dict) -> dict:
    metadata = {}

    def recursive_extract(d, prefix=""):
        if isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, dict):
                    recursive_extract(v, prefix=f"{prefix}{k}_")
                else:
                    if isinstance(v, (str, int, float)):
                        metadata[f"{prefix}{k}"] = str(v)
        elif isinstance(d, list):
            # skip lists for metadata extraction but record length
            metadata[f"{prefix}list_length"] = str(len(d))

    recursive_extract(json_data)
    return metadata


DEFAULT_EMBEDDING = "sentence-transformers/all-MiniLM-L6-v2"


def _docs_from_json_files(json_files: List[str]) -> List[object]:
    # Import Document locally to avoid import-time side-effects
    from langchain.schema import Document
    documents = []
    for json_file in json_files:
        json_data = load_json_text(json_file)
        json_text = json.dumps(json_data, separators=(',', ':'))

        metadata = extract_metadata(json_data)
        metadata["source_file"] = os.path.basename(json_file)

        doc = Document(page_content=json_text, metadata=metadata)
        documents.append(doc)
    return documents


def build_hardcoded_index(index_path: str = "ufdr_faiss_index"):
    """Build a simple text-based index from the hardcoded UFDR report files."""
    print("Building simple text-based index from hardcoded files...")
    
    documents = []
    for json_file in HARDCODED_FILES:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
                json_text = json.dumps(json_data, separators=(',', ':'))
                documents.append({
                    'file': json_file,
                    'content': json_text,
                    'metadata': {"source": json_file}
                })
        except Exception as e:
            print(f"Failed to process {json_file}: {e}")
            continue

    if not documents:
        raise ValueError("No documents could be processed from hardcoded files")

    # Create a simple index structure
    index_data = {
        'total_documents': len(documents),
        'documents': documents,
        'index_created': time.time(),
        'index_type': 'text_based',
        'status': 'ready'
    }
    
    # Ensure directory exists
    os.makedirs(index_path, exist_ok=True)
    
    # Save index metadata
    index_file = os.path.join(index_path, "index_metadata.json")
    with open(index_file, 'w') as f:
        json.dump(index_data, f, indent=2)

    print("✅ Simple text-based index built and saved for hardcoded UFDR files!")
    return f"Successfully created index with {len(documents)} documents"

def build_and_save_index(json_files: Optional[List[str]] = None, index_path: str = "ufdr_faiss_combined_index"):
    """Build a FAISS index from a list of json file paths and save it locally.
    
    If json_files is None, will collect all available JSON files (hardcoded + uploaded).
    Returns the vectorstore instance.
    """
    if json_files is None:
        # Collect all available JSON files
        json_files = []
        
        # Add hardcoded files
        hardcoded_files = ["ufdr_report_1.json", "ufdr_report_2.json", "ufdr_report_3.json"]
        for filename in hardcoded_files:
            if os.path.exists(filename):
                json_files.append(filename)
        
        # Add uploaded files
        uploads_dir = "uploads"
        if os.path.exists(uploads_dir):
            for filename in os.listdir(uploads_dir):
                if filename.endswith('.json'):
                    json_files.append(os.path.join(uploads_dir, filename))
        
        # Add any other JSON files in the directory
        for filename in os.listdir('.'):
            if filename.endswith('.json') and filename not in hardcoded_files:
                json_files.append(filename)

    if not json_files:
        raise ValueError("No JSON files found to build index")

    print(f"Building index from {len(json_files)} files: {json_files}")
    return process_and_add_files(json_files, index_path)

    # local import to avoid heavy imports during module import
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_community.vectorstores import FAISS
    from langchain_huggingface import HuggingFaceEmbeddings

    splitter = RecursiveCharacterTextSplitter(chunk_size=300, chunk_overlap=50)
    print("Splitting documents into chunks...")
    docs = splitter.split_documents(documents)

    embedding_model = HuggingFaceEmbeddings(model_name=DEFAULT_EMBEDDING)

    print("Begin embedding and FAISS index creation...")
    start_time = time.time()
    vectorstore = FAISS.from_documents(docs, embedding_model)
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"FAISS index build done in {elapsed:.2f} seconds.")

    os.makedirs(index_path, exist_ok=True)
    vectorstore.save_local(index_path)
    print(f"\u2705 FAISS index built and saved at {index_path}")
    return vectorstore


def load_index_if_exists(index_path: str = "ufdr_faiss_combined_index"):
    # local imports
    from langchain_community.vectorstores import FAISS
    from langchain_huggingface import HuggingFaceEmbeddings
    embedding_model = HuggingFaceEmbeddings(model_name=DEFAULT_EMBEDDING)

    # First try the provided index path
    if os.path.isdir(index_path):
        try:
            vs = FAISS.load_local(index_path, embedding_model, allow_dangerous_deserialization=True)
            print(f"Loaded existing index from {index_path}")
            return vs
        except Exception as e:
            print(f"Failed to load existing index from {index_path}: {e}")

    # Then try the hardcoded index path
    hardcoded_path = "ufdr_faiss_index"
    if os.path.isdir(hardcoded_path) and hardcoded_path != index_path:
        try:
            vs = FAISS.load_local(hardcoded_path, embedding_model, allow_dangerous_deserialization=True)
            print(f"Loaded existing hardcoded index from {hardcoded_path}")
            return vs
        except Exception as e:
            print(f"Failed to load existing hardcoded index: {e}")

    return None


def process_and_add_files(file_paths: List[str], index_path: str = "ufdr_faiss_combined_index", embeddings_path: str = "embeddings"):
    """Process a list of JSON file paths and create a simple text-based index.
    
    Args:
        file_paths: List of JSON files to process
        index_path: Path to save the combined index
        embeddings_path: Directory to store individual file data
    
    Returns:
        Success message indicating files were processed.
    """
    print(f"Processing {len(file_paths)} files for indexing...")
    
    # Create directories if they don't exist
    os.makedirs(embeddings_path, exist_ok=True)
    os.makedirs(index_path, exist_ok=True)

    # Track processed files
    processed_files_path = "processed_files.json"
    if os.path.exists(processed_files_path):
        with open(processed_files_path, 'r') as f:
            processed_data = json.load(f)
            processed_files = set(processed_data.get('processed_files', []))
    else:
        processed_data = {'processed_files': [], 'uploaded_files_info': []}
        processed_files = set()

    # Process each file
    processed_count = 0
    for file_path in file_paths:
        print(f"Processing {file_path}...")
        try:
            # Read and validate JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Create a simple text index entry
            index_entry = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'size': os.path.getsize(file_path),
                'processed_time': time.time(),
                'data_preview': str(data)[:500] + "..." if len(str(data)) > 500 else str(data)
            }
            
            # Save individual file index
            file_index_path = os.path.join(embeddings_path, os.path.splitext(os.path.basename(file_path))[0] + "_index.json")
            with open(file_index_path, 'w') as f:
                json.dump(index_entry, f, indent=2)
            
            # Update processed files tracking
            processed_files.add(file_path)
            processed_data['processed_files'] = list(processed_files)
            with open(processed_files_path, 'w') as f:
                json.dump(processed_data, f, indent=2)
            
            processed_count += 1
            print(f"✅ Processed {file_path}")
            
        except Exception as e:
            print(f"❌ Failed to process {file_path}: {e}")
            continue

    # Create a combined index file
    combined_index = {
        'total_files': processed_count,
        'processed_files': list(processed_files),
        'index_created': time.time(),
        'index_type': 'text_based',
        'status': 'ready'
    }
    
    combined_index_path = os.path.join(index_path, "index_metadata.json")
    with open(combined_index_path, 'w') as f:
        json.dump(combined_index, f, indent=2)
    
    print(f"✅ Successfully processed {processed_count} files")
    print(f"✅ Index metadata saved to {combined_index_path}")
    
    return f"Successfully processed {processed_count} files and created index"

