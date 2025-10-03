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

# --- Robust JSON loading helpers ---
def _load_json_safely(filepath: str):
    """Load JSON from filepath.

    Tries standard JSON first. If that fails, attempts to parse as NDJSON (one JSON object per line)
    or multiple concatenated JSON objects. Returns either a dict or a list of dicts.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        # Try NDJSON (newline-delimited JSON)
        objs: List[dict] = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        objs.append(obj)
                    except Exception:
                        # Not a pure NDJSON line; fall back to concatenated parsing later
                        objs = []
                        break
            if objs:
                return objs
        except Exception:
            pass

        # Try to split concatenated JSON objects by '}{' boundary
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()
            # Insert a comma between '}{' and wrap with brackets to form a JSON array
            candidate = '[' + data.replace('}\n{', '},{').replace('}{', '},{') + ']'
            return json.loads(candidate)
        except Exception as e:
            raise ValueError(f"Unable to parse JSON file '{os.path.basename(filepath)}': {e}")

def query(q: str, vector_store, db=None, language: str = 'en') -> Dict[str, Any]:
    """Enhanced natural language search focused on the most recently uploaded file.

    Strategy:
    - Prefer the newest JSON file in uploads/ (single-file focus)
    - Fall back to hardcoded ufdr_report_*.json if uploads is empty
    - Answer domain questions with rule-based extractors (case/device/owner/wallets/contacts)
    """
    try:
        target_path = _pick_target_file()
        if not target_path:
            return {
                "answer": "No data files found. Please upload JSON files first.",
                "sources": [],
                "gps": [],
                "session_id": str(time.time())
            }
        data = _load_json_safely(target_path)
        context = _build_context(data)
        answer = _answer_question(q, context)

        # Basic source card for UI
        src = _context_to_source_card(context, target_path)
        return {
            "answer": answer or f"No direct answer found for '{q}'. Try rephrasing or different keywords.",
            "sources": [src] if src else [],
            "gps": context.get('gps', []),
            "session_id": str(time.time())
        }
    except Exception as e:
        print(f"Search error: {str(e)}")
        raise ValueError(f"Search failed: {str(e)}")

# ------------------- Target file selection -------------------
def _pick_target_file() -> Optional[str]:
    uploads_dir = "uploads"
    if os.path.isdir(uploads_dir):
        jsons = [os.path.join(uploads_dir, f) for f in os.listdir(uploads_dir) if f.lower().endswith('.json')]
        if jsons:
            jsons.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            return jsons[0]
    for name in ["ufdr_report_1.json", "ufdr_report_2.json", "ufdr_report_3.json"]:
        if os.path.isfile(name):
            return name
    return None

# ------------------- Context builders -------------------
def _build_context(data: Any) -> dict:
    # If list, consider first dict as primary case
    case = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else data if isinstance(data, dict) else {}
    ctx: dict = {
        'case_id': _find_value(case, ["case_id", "caseid", "caseId", "caseID"]),
        'extraction_date': _find_value(case, ["extraction_date", "extractiondate", "extracted_at", "date", "extractionDate"]),
        'device_model': _find_value(case, ["device_model", "model", "device", "devicename"]),
        'os_version': _find_value(case, ["os_version", "osversion", "os", "android_version", "ios_version"]),
        'imei': _find_value(case, ["imei", "IMEI"]),
        'serial': _find_value(case, ["serial", "serialnumber", "serial_number", "serialNumber"]),
        'timezone': _find_value(case, ["timezone", "time_zone", "tz"]),
        'owner': _find_object(case, ["owner", "ownerinfo", "device_owner", "user", "deviceOwner"]),
        'wallets': _find_list(case, ["shared_wallets", "wallets", "sharedWallets"]),
        'contacts': _extract_contacts(case),
        'gps': _extract_gps(case),
    }
    return ctx

def _extract_gps(d: Any) -> List[dict]:
    pts: List[dict] = []
    def walk(x: Any):
        if isinstance(x, dict):
            if set(x.keys()) >= {"lat", "lon"}:
                try:
                    pts.append({"lat": float(x["lat"]), "lon": float(x["lon"])})
                except Exception:
                    pass
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(d)
    return pts

def _extract_contacts(d: Any) -> List[dict]:
    contacts: List[dict] = []
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
    walk(d)
    # dedupe
    seen = set()
    uniq = []
    for c in contacts:
        key = (c['name'], c['phone'], c['email'])
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq

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
            for v in x:
                r = walk(v)
                if r is not None:
                    return r
        return None
    return walk(d)

def _find_object(d: Any, keys: List[str]) -> dict:
    if not isinstance(d, (dict, list)):
        return {}
    def walk(x: Any) -> Optional[dict]:
        if isinstance(x, dict):
            for k in keys:
                if k in x and isinstance(x[k], dict):
                    return x[k]
            for v in x.values():
                r = walk(v)
                if r is not None:
                    return r
        elif isinstance(x, list):
            for v in x:
                r = walk(v)
                if r is not None:
                    return r
        return None
    return walk(d) or {}

def _find_list(d: Any, keys: List[str]) -> List[Any]:
    if not isinstance(d, (dict, list)):
        return []
    def walk(x: Any) -> Optional[List[Any]]:
        if isinstance(x, dict):
            for k in keys:
                if k in x and isinstance(x[k], list):
                    return x[k]
            for v in x.values():
                r = walk(v)
                if r is not None:
                    return r
        elif isinstance(x, list):
            for v in x:
                r = walk(v)
                if r is not None:
                    return r
        return None
    return walk(d) or []

# ------------------- Question answering -------------------
def _answer_question(q: str, ctx: dict) -> str:
    qt = q.lower().strip()

    # Case & Device Information
    if "case id" in qt and ("extraction" in qt or "date" in qt):
        return f"Case ID: {ctx.get('case_id') or 'N/A'}; Extraction date: {ctx.get('extraction_date') or 'N/A'}."
    if ("device" in qt and ("os" in qt or "version" in qt)) or ("which device" in qt):
        return f"Device: {ctx.get('device_model') or 'N/A'}; OS version: {ctx.get('os_version') or 'N/A'}."
    if ("imei" in qt) or ("serial" in qt):
        return f"IMEI: {ctx.get('imei') or 'N/A'}; Serial: {ctx.get('serial') or 'N/A'}."
    if "timezone" in qt:
        return f"Extraction timezone: {ctx.get('timezone') or 'N/A'}."

    # Owner Information
    if "owner" in qt and ("who" in qt or "name" in qt):
        name = _find_value(ctx.get('owner') or {}, ["name", "owner_name", "full_name"]) or 'N/A'
        return f"Owner: {name}."
    if "owner" in qt and ("phone" in qt or "email" in qt):
        phone = _find_value(ctx.get('owner') or {}, ["phone", "phone_number", "number"]) or 'N/A'
        email = _find_value(ctx.get('owner') or {}, ["email", "mail"]) or 'N/A'
        return f"Owner phone: {phone}; email: {email}."
    if "owner" in qt and ("contact" in qt or "appear" in qt):
        oname = _find_value(ctx.get('owner') or {}, ["name", "owner_name", "full_name"]) or ''
        present = any(c.get('name','').lower() == oname.lower() for c in ctx.get('contacts', [])) if oname else False
        return f"Owner present in contacts: {'Yes' if present else 'No'}."

    # Shared wallets
    if "wallet" in qt:
        wl = ctx.get('wallets') or []
        if "how many" in qt or "count" in qt:
            return f"Shared wallets linked: {len(wl)}."
        if "id" in qt:
            wids = []
            for w in wl:
                if isinstance(w, dict):
                    wid = _find_value(w, ["id", "wallet_id"]) or ''
                    if wid:
                        wids.append(wid)
            return "Wallet IDs: " + (", ".join(wids) if wids else "N/A")

    # Contacts
    contacts = ctx.get('contacts', [])
    if "how many" in qt and "contact" in qt:
        return f"Total contacts: {len(contacts)}."
    if "gmail" in qt:
        gl = [c for c in contacts if c.get('email','').lower().endswith('@gmail.com')]
        return _list_contacts(gl, header="Contacts with Gmail:")
    if "+91" in qt or "starting with +91" in qt:
        gl = [c for c in contacts if c.get('phone','').strip().startswith('+91')]
        return _list_contacts(gl, header="Contacts with +91:")
    if "outlook" in qt:
        gl = [c for c in contacts if c.get('email','').lower().endswith('@outlook.com') or c.get('email','').lower().endswith('@outlook.in')]
        return _list_contacts(gl, header="Outlook contacts:")
    if "rediff" in qt:
        gl = [c for c in contacts if 'rediff' in c.get('email','').lower()]
        return _list_contacts(gl, header="Rediffmail contacts:")
    if "yahoo" in qt:
        gl = [c for c in contacts if c.get('email','').lower().endswith('@yahoo.com')]
        return _list_contacts(gl, header="Yahoo contacts:")
    if "international" in qt or "non-indian" in qt or "foreign" in qt:
        gl = [c for c in contacts if (ph := c.get('phone','')).startswith('+') and not ph.startswith('+91')]
        return _list_contacts(gl, header="International contacts:")
    if "duplicate first name" in qt or "same first name" in qt:
        from collections import Counter
        firsts = [c.get('name','').split()[0] for c in contacts if c.get('name')]
        cnt = Counter([f for f in firsts if f])
        dups = [f"{k} ({v})" for k, v in cnt.items() if v > 1]
        return "Duplicate first names: " + (", ".join(dups) if dups else "None")
    if "contacts named" in qt:
        import re as _re
        m = _re.search(r"contacts named\s+\"?([A-Za-z]+)\"?", qt)
        if m:
            name = m.group(1).lower()
            gl = [c for c in contacts if c.get('name','').lower().split()[0] == name]
            return _list_contacts(gl, header=f"Contacts named {name.capitalize()}:")
    if "starting with" in qt and 'name' in qt:
        import re as _re
        m = _re.search(r"starting with\s+\"?([A-Za-z])\"?", qt)
        if m:
            ch = m.group(1).lower()
            gl = [c for c in contacts if c.get('name','').lower().startswith(ch)]
            return _list_contacts(gl, header=f"Contacts starting with {ch.upper()}:")
    if "unique" in qt and ("domain" in qt or "email" in qt):
        common = {"gmail.com","outlook.com","outlook.in","yahoo.com","rediff.com","rediffmail.com"}
        gl = []
        for c in contacts:
            em = c.get('email','').lower()
            dom = em.split('@')[-1] if '@' in em else ''
            if dom and dom not in common:
                gl.append(c)
        return _list_contacts(gl, header="Contacts with rare email domains:")

    # Mixed queries
    if "share a wallet" in qt or ("owner" in qt and "wallet" in qt):
        oname = _find_value(ctx.get('owner') or {}, ["name", "owner_name", "full_name"]) or ''
        wallet_text = json.dumps(ctx.get('wallets') or [])
        present = oname and (oname.lower() in wallet_text.lower())
        return f"Owner shares a wallet with a listed contact: {'Possibly' if present else 'Not evident'}" 
    if "same last name as the owner" in qt:
        oname = (_find_value(ctx.get('owner') or {}, ["name", "owner_name", "full_name"]) or '').split()
        last = oname[-1].lower() if oname else ''
        gl = [c for c in contacts if last and c.get('name','').lower().split()[-1] == last]
        return _list_contacts(gl, header=f"Contacts with last name '{last.capitalize()}':")
    if "same first name as the owner" in qt:
        oname = (_find_value(ctx.get('owner') or {}, ["name", "owner_name", "full_name"]) or '').split()
        first = oname[0].lower() if oname else ''
        gl = [c for c in contacts if first and c.get('name','').lower().split()[0] == first]
        return f"Contacts sharing owner's first name ({first.capitalize()}): {len(gl)}"

    # Default fallback
    return None

def _list_contacts(items: List[dict], header: str) -> str:
    if not items:
        return header + " None"
    lines = [header]
    for c in items[:50]:
        parts = [p for p in [c.get('name'), c.get('phone'), c.get('email')] if p]
        lines.append(" - " + " | ".join(parts))
    if len(items) > 50:
        lines.append(f"(+{len(items)-50} more)")
    return "\n".join(lines)

# ------------------- Source card helper -------------------
def _context_to_source_card(ctx: dict, filepath: str) -> Optional[dict]:
    try:
        title = f"Case {ctx.get('case_id') or os.path.basename(filepath)}"
        snippet_parts = []
        if ctx.get('device_model') or ctx.get('os_version'):
            snippet_parts.append(f"Device: {ctx.get('device_model') or 'N/A'} | OS: {ctx.get('os_version') or 'N/A'}")
        if ctx.get('extraction_date'):
            snippet_parts.append(f"Extracted: {ctx.get('extraction_date')}")
        owner = ctx.get('owner') or {}
        if isinstance(owner, dict):
            on = owner.get('name') or ''
            if on:
                snippet_parts.append(f"Owner: {on}")
        snippet = " | ".join(snippet_parts) or "UFDR report"
        return {
            "id": ctx.get('case_id') or os.path.basename(filepath),
            "title": title,
            "snippet": snippet,
            "relevance": 0.9,
            "date": ctx.get('extraction_date') or '',
            "type": 'UFDR Report'
        }
    except Exception:
        return None

def _matches_query(query: str, content: str, data: dict) -> bool:
    """Stricter matching to avoid generic matches.

    Require phrase match OR at least 2 whole-word hits, or 1 field hit.
    """
    q = query.strip().lower()
    text = content.lower()
    if not q:
        return False

    # Phrase match
    if q in text:
        return True

    # Whole-word keyword hits
    words = [w for w in re.split(r"\W+", q) if w]
    if not words:
        return False

    def hits(hay: str) -> int:
        return sum(1 for w in words if re.search(rf"\b{re.escape(w)}\b", hay))

    text_hits = hits(text)

    # Field-level hits
    field_texts = []
    for key in ("case_id", "incident_type", "date", "status", "assigned_officer"):
        v = data.get(key)
        if isinstance(v, str):
            field_texts.append(v.lower())
    loc = data.get("location")
    if isinstance(loc, dict) and isinstance(loc.get("address"), str):
        field_texts.append(loc["address"].lower())
    for sub in (data.get("victim"), data.get("suspect")):
        if isinstance(sub, dict):
            for _, v in sub.items():
                if isinstance(v, str):
                    field_texts.append(v.lower())

    field_hits = sum(hits(s) for s in field_texts)

    return text_hits >= 2 or field_hits >= 1

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

def _calculate_relevance(query: str, content: str, data: dict | None = None) -> float:
    """Weighted relevance based on phrase, word and field hits."""
    q = query.lower().strip()
    text = content.lower()
    if not q:
        return 0.0

    score = 0.0
    if q in text:
        score += 0.6

    words = [w for w in re.split(r"\W+", q) if w]
    if words:
        word_hits = sum(1 for w in words if re.search(rf"\b{re.escape(w)}\b", text))
        score += min(0.3, (word_hits / max(1, len(words))) * 0.3)

    field_hits = 0
    if isinstance(data, dict):
        fields = []
        for key in ("case_id", "incident_type", "date", "status", "assigned_officer"):
            v = data.get(key)
            if isinstance(v, str):
                fields.append(v.lower())
        loc = data.get("location")
        if isinstance(loc, dict) and isinstance(loc.get("address"), str):
            fields.append(loc["address"].lower())
        for s in fields:
            for w in words:
                if re.search(rf"\b{re.escape(w)}\b", s):
                    field_hits += 1
    score += min(0.2, field_hits * 0.05)

    if any(w.startswith("ufdr") or w.startswith("case") for w in words):
        score += 0.1

    return max(0.0, min(1.0, score))

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

