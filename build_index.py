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
    """Build a FAISS index from the hardcoded UFDR report files."""
    # Import dependencies here to avoid heavy imports during module import
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_community.vectorstores import FAISS
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain.schema import Document

    documents = []
    for json_file in HARDCODED_FILES:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
                json_text = json.dumps(json_data, separators=(',', ':'))
                doc = Document(page_content=json_text, metadata={"source": json_file})
                documents.append(doc)
        except Exception as e:
            print(f"Failed to process {json_file}: {e}")
            continue

    if not documents:
        raise ValueError("No documents could be processed from hardcoded files")

    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=100)
    docs = splitter.split_documents(documents)

    embedding_model = HuggingFaceEmbeddings(model_name=DEFAULT_EMBEDDING)
    vectorstore = FAISS.from_documents(docs, embedding_model)
    vectorstore.save_local(index_path)

    print("✅ Combined FAISS index built and saved for hardcoded UFDR files!")
    return vectorstore

def build_and_save_index(json_files: Optional[List[str]] = None, index_path: str = "ufdr_faiss_combined_index"):
    """Build a FAISS index from a list of json file paths and save it locally.
    
    If json_files is None, will first try to use hardcoded files, then look for ufdr_report_*.json files.
    Returns the vectorstore instance.
    """
    if json_files is None:
        # Try hardcoded files first
        try:
            return build_hardcoded_index(index_path)
        except Exception as e:
            print(f"Failed to build index from hardcoded files: {e}")
            print("Falling back to searching for UFDR report files in directory...")
            json_files = [p for p in os.listdir('.') if p.startswith('ufdr_report_') and p.endswith('.json')]

    if not json_files:
        raise ValueError("No JSON files provided to build index")

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
    """Process a list of JSON file paths, store individual embeddings, and update the combined index.
    
    Args:
        file_paths: List of JSON files to process
        index_path: Path to save the combined FAISS index
        embeddings_path: Directory to store individual file embeddings
    
    Returns:
        The updated combined vectorstore.
    """
    # Create embeddings directory if it doesn't exist
    os.makedirs(embeddings_path, exist_ok=True)

    # Track processed files
    processed_files_path = "processed_files.json"
    if os.path.exists(processed_files_path):
        with open(processed_files_path, 'r') as f:
            processed_data = json.load(f)
            processed_files = set(processed_data.get('processed_files', []))
    else:
        processed_data = {'processed_files': [], 'uploaded_files_info': []}
        processed_files = set()

    # Only process new files
    new_files = [f for f in file_paths if f not in processed_files]
    if not new_files:
        print("No new files to process")
        return load_index_if_exists(index_path)

    # Import required libraries
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_community.vectorstores import FAISS
    from langchain_huggingface import HuggingFaceEmbeddings

    embedding_model = HuggingFaceEmbeddings(model_name=DEFAULT_EMBEDDING)
    splitter = RecursiveCharacterTextSplitter(chunk_size=300, chunk_overlap=50)

    # Process each new file individually
    for file_path in new_files:
        print(f"Processing {file_path}...")
        try:
            # Create embeddings for this file
            file_docs = _docs_from_json_files([file_path])
            chunked_docs = list(splitter.split_documents(file_docs))
            
            file_vectorstore = FAISS.from_documents(chunked_docs, embedding_model)
            
            # Save individual file embeddings
            file_embeddings_path = os.path.join(embeddings_path, os.path.splitext(os.path.basename(file_path))[0])
            file_vectorstore.save_local(file_embeddings_path)
            
            # Update processed files tracking
            processed_files.add(file_path)
            processed_data['processed_files'] = list(processed_files)
            with open(processed_files_path, 'w') as f:
                json.dump(processed_data, f, indent=2)
            
            print(f"✅ Processed and saved embeddings for {file_path}")
            
        except Exception as e:
            print(f"❌ Failed to process {file_path}: {e}")
            continue

    # Combine all embeddings into the main index
    print("Updating combined index...")
    try:
        combined_vectorstore = None
        
        # Load and combine all embeddings
        for file_path in processed_files:
            file_embeddings_path = os.path.join(embeddings_path, os.path.splitext(os.path.basename(file_path))[0])
            if os.path.exists(file_embeddings_path):
                if combined_vectorstore is None:
                    combined_vectorstore = FAISS.load_local(file_embeddings_path, embedding_model)
                else:
                    file_vectorstore = FAISS.load_local(file_embeddings_path, embedding_model)
                    combined_vectorstore.merge_from(file_vectorstore)

        if combined_vectorstore:
            os.makedirs(index_path, exist_ok=True)
            combined_vectorstore.save_local(index_path)
            print("✅ Combined index updated successfully")
            return combined_vectorstore
        else:
            print("No valid embeddings found to combine")
            return None

    except Exception as e:
        print(f"❌ Failed to update combined index: {e}")
        raise

