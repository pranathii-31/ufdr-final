from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain.schema import Document
from langchain_community.embeddings import HuggingFaceEmbeddings
import os
import json
import time
from typing import List, Optional, Dict, Any
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


def extract_cross_file_metadata(json_files: List[str]) -> Dict[str, List[dict]]:
    """Extract metadata that can be used for cross-file analysis.
    
    Returns:
        Dict with keys like 'contacts', 'phones', 'emails', 'devices', etc.
        Each contains a list of structures with source file info.
    """
    cross_metadata = {
        'contacts': [],
        'phones': [],
        'emails': [],
        'devices': [],
        'wallets': [],
        'case_ids': [],
        'gps_points': []
    }
    
    for file_path in json_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            file_basename = os.path.basename(file_path)
            
            # Extract contacts
            contacts = _extract_contacts_from_data(data)
            for contact in contacts:
                contact['source_file'] = file_basename
                cross_metadata['contacts'].append(contact)
            
            # Extract phones and emails
            for contact in contacts:
                if contact.get('phone'):
                    cross_metadata['phones'].append({
                        'phone': contact['phone'],
                        'name': contact.get('name', ''),
                        'source_file': file_basename
                    })
                if contact.get('email'):
                    cross_metadata['emails'].append({
                        'email': contact['email'],
                        'name': contact.get('name', ''),
                        'source_file': file_basename
                    })
            
            # Extract device info
            device_info = _extract_device_info(data)
            if device_info:
                device_info['source_file'] = file_basename
                cross_metadata['devices'].append(device_info)
            
            # Extract wallets
            wallets = _extract_wallets_from_data(data)
            for wallet in wallets:
                wallet['source_file'] = file_basename
                cross_metadata['wallets'].append(wallet)
            
            # Extract case IDs
            case_id = _extract_case_id(data)
            if case_id:
                cross_metadata['case_ids'].append({
                    'case_id': case_id,
                    'source_file': file_basename
                })
            
            # Extract GPS points
            gps_points = _extract_gps_from_data(data)
            for gps in gps_points:
                gps['source_file'] = file_basename
                cross_metadata['gps_points'].append(gps)
                
        except Exception as e:
            print(f"Warning: Failed to extract metadata from {file_path}: {e}")
            continue
    
    return cross_metadata


def _extract_contacts_from_data(data: dict) -> List[dict]:
    """Extract contact information from JSON data."""
    contacts = []
    
    def is_contact(obj: dict) -> bool:
        keys = {k.lower() for k in obj.keys()}
        return (
            'name' in keys and ('phone' in keys or 'phonenumber' in keys or 'phone_number' in keys or 'number' in keys or 'email' in keys)
        ) or ('first_name' in keys or 'last_name' in keys)
    
    def normalize(obj: dict) -> dict:
        name = obj.get('name') or ' '.join(filter(None, [obj.get('first_name'), obj.get('last_name')]))
        return {
            'name': str(name or '').strip(),
            'phone': str(obj.get('phonenumber') or obj.get('phone') or obj.get('phone_number') or obj.get('number') or '').strip(),
            'email': str(obj.get('email') or obj.get('mail') or '').strip()
        }
    
    def walk(x: Any):
        if isinstance(x, dict):
            if is_contact(x):
                contacts.append(normalize(x))
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                if isinstance(v, dict) and is_contact(v):
                    contacts.append(normalize(v))
                walk(v)
    
    walk(data)
    
    # dedupe by name + phone
    seen = set()
    unique_contacts = []
    for c in contacts:
        key = (c['name'], c['phone'])
        if key not in seen and (c['name'] or c['phone'] or c['email']):
            seen.add(key)
            unique_contacts.append(c)
    
    return unique_contacts


def _extract_device_info(data: dict) -> Optional[dict]:
    """Extract device information from JSON data."""
    device_info = {}
    
    def _find_value(d: Any, keys: List[str]) -> Optional[str]:
        if not isinstance(d, (dict, list)):
            return None
        def walk(x: Any) -> Optional[str]:
            if isinstance(x, dict):
                for k in keys:
                    if k in x and isinstance(x[k], (str, int, float)):
                        return str(x[k])
                for v in x.values():
                    r = walk(v)
                    if r is not None:
                        return r
            elif isinstance(x, list):
                for item in x:
                    r = walk(item)
                    if r is not None:
                        return r
            return None
        return walk(d)
    
    device_info['device_model'] = _find_value(data, ["device_model", "model", "device", "devicename"])
    device_info['imei'] = _find_value(data, ["imei", "IMEI"])
    device_info['serial'] = _find_value(data, ["serial", "serialnumber", "serial_number", "serialNumber"])
    device_info['os_version'] = _find_value(data, ["os_version", "osversion", "os", "android_version", "ios_version"])
    
    return device_info if any(device_info.values()) else None


def _extract_wallets_from_data(data: dict) -> List[dict]:
    """Extract wallet information from JSON data."""
    wallets = []
    
    def walk(x: Any):
        if isinstance(x, dict):
            # Check if this looks like a wallet object
            keys = {k.lower() for k in x.keys()}
            if any(word in keys for word in ['wallet', 'address', 'addresses', 'balance', 'amount']):
                wallet_info = {
                    'address': x.get('address') or x.get('wallet') or x.get('addresses'),
                    'balance': x.get('balance') or x.get('amount') or x.get('total'),
                    'type': x.get('type') or x.get('wallet_type')
                }
                if wallet_info['address']:
                    wallets.append(wallet_info)
            
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                if isinstance(v, dict):
                    walk(v)
    
    walk(data)
    return wallets


def _extract_case_id(data: dict) -> Optional[str]:
    """Extract case ID from JSON data."""
    def _find_value(d: Any, keys: List[str]) -> Optional[str]:
        if not isinstance(d, (dict, list)):
            return None
        def walk(x: Any) -> Optional[str]:
            if isinstance(x, dict):
                for k in keys:
                    if k in x and isinstance(x[k], (str, int, float)):
                        return str(x[k])
                for v in x.values():
                    r = walk(v)
                    if r is not None:
                        return r
            elif isinstance(x, list):
                for item in x:
                    r = walk(item)
                    if r is not None:
                        return r
            return None
        return walk(d)
    
    return _find_value(data, ["case_id", "caseid", "caseId", "caseID"])


def _extract_gps_from_data(data: dict) -> List[dict]:
    """Extract GPS coordinates from JSON data."""
    gps_points = []
    
    def walk(x: Any):
        if isinstance(x, dict):
            if set(x.keys()) >= {"lat", "lon"} or set(x.keys()) >= {"latitude", "longitude"}:
                try:
                    lat_key = "lat" if "lat" in x else "latitude"
                    lon_key = "lon" if "lon" in x else "longitude"
                    gps_points.append({
                        "lat": float(x[lat_key]), 
                        "lon": float(x[lon_key]),
                        "timestamp": x.get('timestamp', ''),
                        "address": x.get('address', '')
                    })
                except Exception:
                    pass
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    
    walk(data)
    return gps_points


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
    """Lightweight loader for the simplified text-based index.

    Returns metadata dict if present, otherwise None. Avoids importing ML libs.
    """
    metadata_file = os.path.join(index_path, "index_metadata.json")
    if os.path.isfile(metadata_file):
        try:
            with open(metadata_file, 'r') as f:
                meta = json.load(f)
            print(f"Loaded simple index metadata from {metadata_file}")
            return meta
        except Exception as e:
            print(f"Failed to read index metadata: {e}")
            return None

    # Also check legacy hardcoded path used earlier
    hardcoded_path = "ufdr_faiss_index"
    metadata_file2 = os.path.join(hardcoded_path, "index_metadata.json")
    if os.path.isfile(metadata_file2):
        try:
            with open(metadata_file2, 'r') as f:
                meta = json.load(f)
            print(f"Loaded simple index metadata from {metadata_file2}")
            return meta
        except Exception as e:
            print(f"Failed to read hardcoded index metadata: {e}")
            return None

    return None


def process_and_add_files(file_paths: List[str], index_path: str = "ufdr_faiss_combined_index", embeddings_path: str = "embeddings"):
    """Process a list of JSON file paths and create a simple text-based index with cross-file metadata.
    
    Args:
        file_paths: List of JSON files to process
        index_path: Path to save the combined index
        embeddings_path: Directory to store individual file data
    
    Returns:
        combined_index structure for enhanced query capabilities
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

    # Extract cross-file metadata for enhanced queries
    print("Extracting cross-file metadata...")
    cross_metadata = extract_cross_file_metadata(file_paths)
    
    # Process each file
    processed_count = 0
    file_details = {}
    
    for file_path in file_paths:
        print(f"Processing {file_path}...")
        try:
            # Read and validate JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            file_basename = os.path.basename(file_path)
            
            # Create enhanced index entry with cross-file capabilities
            index_entry = {
                'file_path': file_path,
                'file_name': file_basename,
                'size': os.path.getsize(file_path),
                'processed_time': time.time(),
                'data_preview': str(data)[:500] + "..." if len(str(data)) > 500 else str(data),
                'contacts_count': len([c for c in cross_metadata['contacts'] if c.get('source_file') == file_basename]),
                'device_info': next((d for d in cross_metadata['devices'] if d.get('source_file') == file_basename), {}),
                'case_id': next((c['case_id'] for c in cross_metadata['case_ids'] if c.get('source_file') == file_basename), None)
            }
            
            file_details[file_basename] = index_entry
            
            # Save individual file index
            file_index_path = os.path.join(embeddings_path, os.path.splitext(file_basename)[0] + "_index.json")
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

    # Create enhanced combined index file with cross-file analysis capabilities
    combined_index = {
        'total_files': processed_count,
        'processed_files': list(processed_files),
        'index_created': time.time(),
        'index_type': 'text_based_with_cross_file',
        'status': 'ready',
        'file_details': file_details,
        'cross_file_metadata': cross_metadata,
        'analysis_summary': {
            'total_contacts': len(cross_metadata['contacts']),
            'unique_phones': len(set(c['phone'] for c in cross_metadata['phones'] if c['phone'])),
            'unique_emails': len(set(c['email'] for c in cross_metadata['emails'] if c['email'])),
            'total_devices': len(cross_metadata['devices']),
            'total_wallets': len(cross_metadata['wallets']),
            'gps_locations': len(cross_metadata['gps_points']),
            'case_ids': list(set(c['case_id'] for c in cross_metadata['case_ids'] if c['case_id']))
        }
    }
    
    combined_index_path = os.path.join(index_path, "index_metadata.json")
    with open(combined_index_path, 'w') as f:
        json.dump(combined_index, f, indent=2)
    
    # Save cross-file analysis separately for easy access
    cross_analysis_path = os.path.join(index_path, "cross_file_analysis.json")
    with open(cross_analysis_path, 'w') as f:
        json.dump(cross_metadata, f, indent=2)
    
    print(f"✅ Successfully processed {processed_count} files")
    print(f"✅ Index metadata saved to {combined_index_path}")
    print(f"✅ Cross-file analysis saved to {cross_analysis_path}")
    print(f"📊 Found {combined_index['analysis_summary']['total_contacts']} contacts across {processed_count} files")
    print(f"📱 Found {combined_index['analysis_summary']['unique_phones']} unique phone numbers")
    print(f"📧 Found {combined_index['analysis_summary']['unique_emails']} unique email addresses")
    
    return combined_index

