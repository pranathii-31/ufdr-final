# import os
# from dotenv import load_dotenv
# from rich.console import Console

# from langchain_community.vectorstores import FAISS
# from langchain.chains.retrieval_qa.base import RetrievalQA
# from langchain.agents import initialize_agent, Tool
# from langchain.memory import ConversationBufferMemory
# from langchain_huggingface import HuggingFaceEmbeddings
# from langchain_groq import ChatGroq

# # Load environment variables (including API keys)
# load_dotenv()

# # Optional: Disable TensorFlow usage in transformers if not needed
# os.environ["USE_TF"] = "0"
# os.environ["TRANSFORMERS_NO_TF"] = "1"
# os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

# # Check API key environment variable
# api_key = os.getenv("GROQ_API_KEY")
# if not api_key:
#     raise ValueError("GROQ_API_KEY environment variable not set. Please set it in your .env file or environment.")

# # Set up conversation memory
# memory = ConversationBufferMemory(return_messages=True)

# # Load embedding model and FAISS vectorstore index
# embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
# vectorstore = FAISS.load_local("json_faiss_index", embedding_model, allow_dangerous_deserialization=True)
# retriever = vectorstore.as_retriever(search_kwargs={"k": 10})


# # Initialize language model with API key
# llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0.7, api_key=api_key)


# # Create QA chain and wrap in a Tool
# qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)
# qa_tool = Tool(
#     name="QA",
#     func=lambda q: qa_chain.invoke({"query": q})["result"],
#     description="Retrieve relevant information from the dataset."
# )

# # Initialize agent with tools, memory, and LLM
# agent = initialize_agent(
#     tools=[qa_tool],
#     llm=llm,
#     agent="zero-shot-react-description",
#     memory=memory,
#     verbose=True
# )

# # Interactive chat loop
# print("Assistant is ready! Type 'q' to quit.")
# console = Console()

# while True:
#     query = input("You: ")
#     if query.lower() == "q":
#         break

#     result = agent.invoke(query)
#     output = result.get("output", result)

#     console.print("\n[bold cyan]AI Response:[/bold cyan]\n")
#     console.print(output)

import os
import json
import re
import time
from typing import Any, Dict, Optional, List, Tuple
from dotenv import load_dotenv

load_dotenv()

def query(q: str, vector_store, db=None, language: str = 'en') -> Dict[str, Any]:
    """Enhanced natural language search with uploaded files support."""
    try:
        # Get all JSON files (both hardcoded and uploaded)
        json_files = []
        
        # Check for hardcoded files
        hardcoded_files = ["ufdr_report_1.json", "ufdr_report_2.json", "ufdr_report_3.json"]
        for filename in hardcoded_files:
            if os.path.exists(filename):
                json_files.append(filename)
        
        # Check for uploaded files in uploads directory
        uploads_dir = "uploads"
        if os.path.exists(uploads_dir):
            for filename in os.listdir(uploads_dir):
                if filename.endswith('.json'):
                    json_files.append(os.path.join(uploads_dir, filename))
        
        if not json_files:
            return {
                "answer": "No data files found. Please upload JSON files first.",
                "sources": [],
                "gps": [],
                "session_id": str(time.time())
            }
        
        results = []
        
        # Process each JSON file
        for filepath in json_files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Handle different JSON structures
                if isinstance(data, list):
                    # If it's a list of cases
                    for case in data:
                        content = json.dumps(case, separators=(',', ':'))
                        if _matches_query(q, content, case):
                            results.append({
                                'content': content,
                                'metadata': _extract_metadata(case, filepath)
                            })
                elif isinstance(data, dict):
                    # If it's a single case or structured data
                    content = json.dumps(data, separators=(',', ':'))
                    if _matches_query(q, content, data):
                        results.append({
                            'content': content,
                            'metadata': _extract_metadata(data, filepath)
                        })
                        
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
                continue
        
        if not results:
            return {
                "answer": f"No relevant information found for '{q}'. Try searching for: fraud, cybercrime, homicide, case numbers, locations, or evidence types.",
                "sources": [],
                "gps": [],
                "session_id": str(time.time())
            }
        
        # Sort by relevance (simple scoring)
        results = sorted(results, key=lambda x: _calculate_relevance(q, x['content']), reverse=True)
        
        # Format response
        sources = []
        gps_coords = []
        
        for result in results[:5]:  # Limit to top 5
            metadata = result['metadata']
            content = result['content']
            
            # Create formatted source entry
            source_entry = {
                "title": f"Case {metadata.get('case_id', metadata.get('id', 'Unknown'))}",
                "snippet": _create_snippet(content, q),
                "relevance": min(0.95, _calculate_relevance(q, content)),
                "date": metadata.get('date', metadata.get('incident_date', 'Unknown')),
                "type": metadata.get('incident_type', metadata.get('type', 'Unknown')),
                "id": metadata.get('case_id', metadata.get('id', 'Unknown'))
            }
            sources.append(source_entry)
            
            # Extract GPS coordinates
            coords = metadata.get('coordinates', metadata.get('location', {}).get('coordinates', {}))
            if coords and isinstance(coords, dict) and 'lat' in coords and 'lon' in coords:
                gps_coords.append({
                    "lat": coords['lat'],
                    "lon": coords['lon'],
                    "source": metadata.get('source', 'Unknown')
                })
        
        # Create comprehensive answer
        answer_parts = []
        for i, result in enumerate(results[:3]):
            answer_parts.append(f"**Result {i+1}:** {_create_snippet(result['content'], q, 400)}")
        
        answer_text = "\n\n".join(answer_parts)

        return {
            "answer": answer_text,
            "sources": sources,
            "gps": gps_coords,
            "session_id": str(time.time())
        }
    except Exception as e:
        print(f"Search error: {str(e)}")
        raise ValueError(f"Search failed: {str(e)}")

def _matches_query(query: str, content: str, data: dict) -> bool:
    """Check if content matches the query using various matching strategies."""
    query_lower = query.lower()
    content_lower = content.lower()
    
    # Direct keyword matching
    keywords = query_lower.split()
    if any(keyword in content_lower for keyword in keywords):
        return True
    
    # Semantic matching for common terms
    semantic_map = {
        'fraud': ['financial', 'money', 'theft', 'embezzlement', 'scam'],
        'cybercrime': ['hacking', 'phishing', 'malware', 'data breach', 'cyber'],
        'homicide': ['murder', 'killing', 'death', 'fatal'],
        'theft': ['stealing', 'robbery', 'burglary', 'larceny'],
        'assault': ['attack', 'violence', 'battery', 'harm']
    }
    
    for term, synonyms in semantic_map.items():
        if term in query_lower:
            if any(syn in content_lower for syn in synonyms):
                return True
    
    return False

def _extract_metadata(data: dict, filepath: str) -> dict:
    """Extract metadata from case data."""
    metadata = {
        'source': os.path.basename(filepath),
        'case_id': data.get('case_id', data.get('id', 'Unknown')),
        'incident_type': data.get('incident_type', data.get('type', 'Unknown')),
        'date': data.get('date', data.get('incident_date', 'Unknown')),
        'coordinates': data.get('location', {}).get('coordinates', {}) if isinstance(data.get('location'), dict) else {}
    }
    
    # Extract additional fields
    if 'victim' in data:
        metadata['victim'] = data['victim']
    if 'suspect' in data:
        metadata['suspect'] = data['suspect']
    if 'evidence' in data:
        metadata['evidence_count'] = len(data['evidence']) if isinstance(data['evidence'], list) else 1
    
    return metadata

def _calculate_relevance(query: str, content: str) -> float:
    """Calculate relevance score for search results."""
    query_lower = query.lower()
    content_lower = content.lower()
    
    score = 0.0
    
    # Exact phrase match
    if query_lower in content_lower:
        score += 0.8
    
    # Keyword matches
    keywords = query_lower.split()
    matches = sum(1 for keyword in keywords if keyword in content_lower)
    score += (matches / len(keywords)) * 0.6
    
    # Case ID matches (high priority)
    if any(keyword.startswith('ufdr') or keyword.startswith('case') for keyword in keywords):
        score += 0.3
    
    return min(1.0, score)

def _create_snippet(content: str, query: str, max_length: int = 200) -> str:
    """Create a relevant snippet from content."""
    query_lower = query.lower()
    content_lower = content.lower()
    
    # Find the best matching section
    if query_lower in content_lower:
        start = content_lower.find(query_lower)
        snippet_start = max(0, start - 50)
        snippet_end = min(len(content), start + len(query) + 150)
        snippet = content[snippet_start:snippet_end]
        
        if snippet_start > 0:
            snippet = "..." + snippet
        if snippet_end < len(content):
            snippet = snippet + "..."
            
        return snippet
    
    # Fallback to beginning of content
    return content[:max_length] + "..." if len(content) > max_length else content

    if llm is not None:
        try:
            # If language provided, ask the model to respond in that language
            lang_name = {
                'en': 'English', 'es': 'Spanish', 'fr': 'French'
            }.get(language, language)
            prompt = f"Please answer the following question in {lang_name}:\n\n{q}"
            qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever, chain_type="stuff")
            answer_text = qa_chain.run(prompt)
        except Exception as e:
            # If LLM call fails (invalid key or network), fall back to retrieval-only snippets
            print('LLM call failed, falling back to retrieval-only:', e)
            docs = retriever.get_relevant_documents(q)
            snippets = [d.page_content[:500] for d in docs]
            answer_text = "\n---\n".join(snippets)
    else:
        # If no LLM, return concatenated retrieved documents as answer
        docs = retriever.get_relevant_documents(q)
        snippets = [d.page_content[:500] for d in docs]
        answer_text = "\n---\n".join(snippets)

    # collect source metadata and try to extract GPS coordinates if present
    docs = retriever.get_relevant_documents(q)
    sources: List[dict] = []
    gps_points: List[dict] = []

    def try_parse_coords_from_text(text: str) -> Optional[Tuple[float, float]]:
        if not text:
            return None
        # decimal degrees pattern: lat, lon or lon, lat (simple)
        m = re.search(r"(-?\d{1,3}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)", text)
        if m:
            try:
                a = float(m.group(1))
                b = float(m.group(2))
                # make a best-effort: lat should be between -90 and 90
                if -90 <= a <= 90 and -180 <= b <= 180:
                    return (a, b)
                if -90 <= b <= 90 and -180 <= a <= 180:
                    return (b, a)
            except Exception:
                pass
        # named patterns: lat: 12.34 lon: -56.78
        mlat = re.search(r"lat(?:itude)?[:=\s]+(-?\d{1,3}\.\d+)", text, re.IGNORECASE)
        mlon = re.search(r"lon(?:gitude)?|lng[:=\s]+(-?\d{1,3}\.\d+)", text, re.IGNORECASE)
        # above regex for lon may not capture group for some patterns; try a more explicit pair
        if mlat and mlon:
            try:
                return (float(mlat.group(1)), float(mlon.group(1)))
            except Exception:
                pass
        return None

    for d in docs:
        sources.append(d.metadata)
        lat = None
        lon = None
        # Check metadata for common coordinate keys
        for k, v in d.metadata.items():
            lower_k = str(k).lower()
            try:
                # direct numeric values
                if isinstance(v, (int, float)):
                    if 'lat' in lower_k or 'latitude' in lower_k:
                        lat = float(v)
                    if 'lon' in lower_k or 'lng' in lower_k or 'longitude' in lower_k:
                        lon = float(v)
                # string values that may contain comma-separated coords
                elif isinstance(v, str):
                    # value like "12.34, -56.78"
                    m = re.search(r"(-?\d{1,3}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)", v)
                    if m and lat is None and lon is None:
                        lat = float(m.group(1))
                        lon = float(m.group(2))
                    # single numeric string
                    if ('lat' in lower_k or 'latitude' in lower_k) and lat is None:
                        try:
                            lat = float(v)
                        except Exception:
                            pass
                    if ('lon' in lower_k or 'lng' in lower_k or 'longitude' in lower_k) and lon is None:
                        try:
                            lon = float(v)
                        except Exception:
                            pass
                # lists or tuples e.g. [lat, lon]
                elif isinstance(v, (list, tuple)) and len(v) >= 2:
                    try:
                        maybe_lat = float(v[0])
                        maybe_lon = float(v[1])
                        if -90 <= maybe_lat <= 90 and -180 <= maybe_lon <= 180:
                            lat = maybe_lat
                            lon = maybe_lon
                    except Exception:
                        pass
            except Exception:
                continue

        # If metadata didn't contain coords, try scanning page content
        if (lat is None or lon is None) and hasattr(d, 'page_content'):
            parsed = try_parse_coords_from_text(d.page_content)
            if parsed:
                lat, lon = parsed

        if lat is not None and lon is not None:
            gps_points.append({"lat": lat, "lon": lon, "source": d.metadata.get('source_file') or d.metadata.get('file_path')})

    # persist a minimal chat history entry (session id is timestamp)
    session_id = str(int(time.time()))
    timestamp = int(time.time())

    # If a DB session is provided, use the ORM to store the entry
    if db is not None:
        try:
            from models import ChatEntry
            ce = ChatEntry(session_id=session_id, timestamp=timestamp, query=q, answer=answer_text, sources=sources)
            db.add(ce)
            db.commit()
        except Exception as e:
            print('Failed to write chat history to DB', e)

    return {"answer": answer_text, "sources": sources, "gps": gps_points, "session_id": session_id}

