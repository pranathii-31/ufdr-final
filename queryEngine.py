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

# queryEngine provides a function-based query interface so FastAPI can call it.
def query(q: str, vector_store, db=None, language: str = 'en') -> Dict[str, Any]:
    """Run a retrieval QA against the provided vector_store and return a structured result.

    Returns: {answer: str, sources: [metadata], gps: [{lat, lon}], session_id: str}
    """
    try:
        if vector_store is None:
            # Try to load the index if it exists
            try:
                from langchain.vectorstores import FAISS
                from langchain_community.embeddings import HuggingFaceEmbeddings
                
                embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
                vector_store = FAISS.load_local("ufdr_faiss_index", embeddings)
                print("Successfully loaded existing index")
            except Exception as e:
                print(f"Failed to load index: {str(e)}")
                raise ValueError("Vector store is not initialized. Please rebuild the index first.")

        # Build retriever on the provided vector_store
        retriever = vector_store.as_retriever(search_kwargs={"k": 5})
        
        print(f"Searching for query: {q}")
        # Get raw context from retriever
        raw_docs = retriever.get_relevant_documents(q)
        print(f"Found {len(raw_docs)} relevant documents")
        
        # Format response
        sources = []
        gps_coords = []
        
        for doc in raw_docs:
            if hasattr(doc, 'metadata'):
                sources.append(doc.metadata)
                
                # Extract GPS coordinates if available
                if 'gps' in doc.metadata:
                    try:
                        gps = doc.metadata['gps']
                        if isinstance(gps, dict) and 'lat' in gps and 'lon' in gps:
                            gps_coords.append(gps)
                    except Exception as e:
                        print(f"Error processing GPS data: {str(e)}")
                        pass

        return {
            "answer": "\n".join([doc.page_content for doc in raw_docs]),
            "sources": sources,
            "gps": gps_coords,
            "session_id": str(time.time())
        }
    except Exception as e:
        print(f"Search error: {str(e)}")
        raise ValueError(f"Search failed: {str(e)}")

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

