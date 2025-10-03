from fastapi import FastAPI, HTTPException, Depends, status, Response, UploadFile, File, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
import models, schemas, utils
from utils import init_db
import build_index
import queryEngine
import uuid
import shutil
import io
from fastapi.responses import StreamingResponse, FileResponse
from fpdf import FPDF
from gtts import gTTS
from datetime import datetime, timedelta
import jwt
import os
import json
import time
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()

# JWT settings
SECRET_KEY = "your-secret-key-change-in-production"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get('sub')
        if email is None:
            raise HTTPException(status_code=401, detail='Invalid authentication credentials')
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid authentication credentials')
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail='User not found')
    return user

# Use shared schemas for request models
from schemas import QueryRequest

# Initialize vector_store lazily on first query
vector_store = None

@app.on_event("startup")
async def startup_event():
    print("Starting application initialization...")
    try:
        # Close any existing connections
        engine.dispose()
        print("Closed existing database connections")
        
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)
        print("Database tables verified/created successfully")
        
        # Initialize database with test user if needed
        db = SessionLocal()
        try:
            # Check and create test user
            test_user = db.query(models.User).filter(models.User.email == "test@example.com").first()
            if not test_user:
                print("Creating test user...")
                salt = utils.generate_salt()
                password = "testpassword"  # Default test password
                hashed_password = utils.hash_password(password, salt)
                
                test_user = models.User(
                    email="test@example.com",
                    hashed_password=hashed_password,
                    salt=salt
                )
                db.add(test_user)
                db.commit()
                print("Test user created successfully:")
                print(f"Email: test@example.com")
                print(f"Password: {password}")
            else:
                print("Test user exists:", test_user.email)
                # Verify test user credentials are valid
                is_valid = utils.verify_password(test_user.hashed_password, test_user.salt, "testpassword")
                print(f"Test user password verification: {'Success' if is_valid else 'Failed'}")
            
            print("Database initialization completed successfully")
            
        except Exception as e:
            print(f"Error initializing test user: {str(e)}")
            db.rollback()
            raise
        finally:
            db.close()
            
    except Exception as e:
        print(f"Error during startup: {str(e)}")
        raise
    
    print("Application startup completed successfully")

@app.on_event("shutdown")
async def shutdown_event():
    print("Starting application shutdown...")
    try:
        # Close all database connections
        engine.dispose()
        print("All database connections closed")
        
        # Cleanup any temporary files if needed
        # Add any additional cleanup tasks here
        
        print("Application shutdown completed successfully")
    except Exception as e:
        print(f"Error during shutdown: {str(e)}")
        raise

@app.get("/")
async def root():
    return {"message": "FastAPI backend running"}

@app.get("/index-status")
async def index_status():
    """Return whether the vector index is available and basic metadata if present."""
    global vector_store
    status = {"loaded": False}
    try:
        if vector_store is None:
            # attempt lazy load without building
            vs = build_index.load_index_if_exists()
            if vs is not None:
                vector_store = vs
        if vector_store is not None:
            status["loaded"] = True
            # try to expose minimal info when available
            try:
                size = getattr(vector_store, "index", None)
                status["size"] = getattr(size, "ntotal", None)
            except Exception:
                pass
    except Exception as e:
        status["error"] = str(e)
    return status

@app.post("/build_index")
async def build_index_endpoint(current_user: models.User = Depends(get_current_user)):
    global vector_store
    try:
        print("Starting index rebuild...")
        result = build_index.build_and_save_index()
        print(f"Index rebuild result: {result}")
        
        # log audit
        try:
            db = SessionLocal()
            log_audit(db, user=current_user.email, action='rebuild_index')
        except Exception:
            pass
        
        return {
            "status": "success", 
            "message": "Index rebuilt successfully",
            "details": result
        }
    except Exception as e:
        print(f"Index rebuild error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Index rebuild failed: {str(e)}")


def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_audit(db, user: str, action: str, extra: dict | None = None):
    try:
        entry = models.AuditLog(user=user, action=action, extra=extra or {})
        db.add(entry)
        db.commit()
    except Exception as e:
        print('Failed to log audit', e)


@app.post('/upload')
async def upload_files(files: list[UploadFile] = File(...), current_user: models.User = Depends(get_current_user), background_tasks: BackgroundTasks = None):
    """Accept multiple uploaded files, save them, and process for indexing."""
    try:
        print("Starting file upload process...")
        os.makedirs('uploads', exist_ok=True)
        
        # Create DB session
        print("Creating database session...")
        db = SessionLocal()
        uploaded_info = []
        saved_paths = []
        
        print(f"Processing {len(files)} files...")
        for up in files:
            try:
                print(f"Processing file: {up.filename}")
                
                # Validate file type
                if not up.filename.lower().endswith('.json'):
                    raise HTTPException(status_code=400, detail=f"Only JSON files are supported. {up.filename} is not a JSON file.")
                
                # Use original filename for easier identification
                save_name = up.filename
                save_path = os.path.join('uploads', save_name)
                
                # Handle duplicate filenames
                counter = 1
                while os.path.exists(save_path):
                    name, ext = os.path.splitext(up.filename)
                    save_name = f"{name}_{counter}{ext}"
                    save_path = os.path.join('uploads', save_name)
                    counter += 1
                
                print(f"Saving file to: {save_path}")
                try:
                    with open(save_path, 'wb') as out_f:
                        content = await up.read()
                        out_f.write(content)
                    saved_paths.append(save_path)
                    print(f"File saved successfully")
                    
                    # Validate JSON content
                    try:
                        with open(save_path, 'r', encoding='utf-8') as f:
                            json.load(f)
                        print(f"JSON validation successful for {up.filename}")
                    except json.JSONDecodeError as e:
                        print(f"Invalid JSON in {up.filename}: {e}")
                        os.remove(save_path)  # Remove invalid file
                        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {up.filename}")
                        
                except Exception as e:
                    print(f"Error saving file: {str(e)}")
                    raise HTTPException(status_code=500, detail=f"Error saving file {up.filename}: {str(e)}")

                print("Creating file info record")
                file_id = str(uuid.uuid4())
                info = {
                    "id": file_id,
                    "original_name": up.filename,
                    "file_path": save_path.replace('\\', '/'),
                    "size": os.path.getsize(save_path),
                    "upload_time": datetime.utcnow().isoformat(),
                    "type": up.content_type or 'application/json',
                    "processed": True
                }
                uploaded_info.append(info)

                print("Saving to database")
                try:
                    file_record = models.UploadedFile(
                        id=file_id,
                        original_name=up.filename,
                        file_path=save_path,
                        size=os.path.getsize(save_path),
                        upload_time=datetime.utcnow(),
                        type=up.content_type or 'application/json',
                        processed=True,
                        user_id=current_user.id
                    )
                    db.add(file_record)
                    print("Database record created")
                except Exception as e:
                    print(f"Database error: {str(e)}")
                    raise
                
            except Exception as e:
                print(f"Error processing file {up.filename}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error processing file {up.filename}: {str(e)}")

        try:
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        finally:
            db.close()

        return {
            "status": "success",
            "message": f"Successfully uploaded {len(uploaded_info)} files. You can now search through them or rebuild the index for better performance.",
            "files": uploaded_info
        }
        
    except Exception as e:
        print(f"Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
        global vector_store
        vector_store = build_index.process_and_add_files(saved_paths)
        # mark processed true in DB
        for p in saved_paths:
            db.query(models.UploadedFile).filter(models.UploadedFile.file_path == p).update({"processed": True})
        db.commit()
        try:
            log_audit(db, user=current_user.email, action='upload', extra={'files': [os.path.basename(p) for p in saved_paths]})
        except Exception:
            pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload saved but processing failed: {e}")

    return {"status": "uploaded and processed", "files": uploaded_info}


@app.get('/files')
async def list_files():
    db = SessionLocal()
    files = db.query(models.UploadedFile).all()
    return [
        {"id": f.file_id, "original_name": f.original_name, "file_path": f.file_path, "size": f.size, "upload_time": f.upload_time.isoformat() if f.upload_time else None, "type": f.type, "processed": f.processed}
        for f in files
    ]


@app.get('/analytics')
async def analytics():
    db = SessionLocal()
    files = db.query(models.UploadedFile).all()
    stats = {"total_files": len(files), "total_size": sum(f.size or 0 for f in files), "cases": 0, "types": {}}
    for f in files:
        try:
            with open(f.file_path, 'r', encoding='utf-8') as fh:
                j = json.load(fh)
                if isinstance(j, dict):
                    if 'cases' in j and isinstance(j['cases'], list):
                        stats['cases'] += len(j['cases'])
                    else:
                        for k, v in j.items():
                            if isinstance(v, list):
                                stats['cases'] += len(v)
                                stats['types'][k] = stats['types'].get(k, 0) + len(v)
                elif isinstance(j, list):
                    stats['cases'] += len(j)
        except Exception:
            continue
    return stats


@app.get('/chat-history/{session_id}')
async def get_chat_history(session_id: str):
    db = SessionLocal()
    entries = db.query(models.ChatEntry).filter(models.ChatEntry.session_id == session_id).order_by(models.ChatEntry.timestamp).all()
    return [{"session_id": e.session_id, "timestamp": e.timestamp, "query": e.query, "answer": e.answer, "sources": e.sources} for e in entries]


@app.get('/audit-logs')
async def get_audit_logs(user: str | None = None, action: str | None = None, page: int = 1, page_size: int = 50, current_user: models.User = Depends(get_current_user)):
    """Return audit logs with optional filtering and pagination.

    Query params:
    - user: filter by user email
    - action: filter by action (exact)
    - page: 1-based page number
    - page_size: items per page (max 500)
    """
    db = SessionLocal()
    try:
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        q = db.query(models.AuditLog)
        if user:
            q = q.filter(models.AuditLog.user == user)
        if action:
            q = q.filter(models.AuditLog.action == action)
        total = q.count()
        logs = q.order_by(models.AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        results = [{"id": l.id, "user": l.user, "action": l.action, "extra": l.extra, "timestamp": l.timestamp} for l in logs]
        return {"total": total, "page": page, "page_size": page_size, "items": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/chat-history/{session_id}')
async def save_chat_message(session_id: str, msg: dict):
    db = SessionLocal()
    entry = models.ChatEntry(session_id=session_id, timestamp=int(time.time()), query=msg.get('query',''), answer=msg.get('answer',''), sources=msg.get('sources', []))
    db.add(entry)
    db.commit()
    return {"status": "ok"}


@app.get('/export-pdf/{session_id}')
async def export_pdf(session_id: str, current_user: models.User = Depends(get_current_user)):
    # Create a PDF containing all chat entries for the session
    db = SessionLocal()
    entries = db.query(models.ChatEntry).filter(models.ChatEntry.session_id == session_id).order_by(models.ChatEntry.timestamp).all()
    if not entries:
        raise HTTPException(status_code=404, detail='Session not found')
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font('Arial', size=12)
    pdf.cell(0, 10, f'Session: {session_id}', ln=True)
    pdf.ln(4)
    for e in entries:
        # e may be ORM objects
        if hasattr(e, 'timestamp'):
            timestamp = e.timestamp
            q = e.query
            a = e.answer
        else:
            timestamp = e.get('timestamp')
            q = e.get('query')
            a = e.get('answer')
        tstr = datetime.utcfromtimestamp(timestamp).isoformat() if timestamp else ''
        pdf.multi_cell(0, 8, f"[{tstr}] QUERY: {q}")
        pdf.multi_cell(0, 8, f"ANSWER:\n{a}")
        pdf.ln(2)

    # FPDF.output with a file-like buffer is not supported in this version.
    # Use dest='S' to get the PDF as a string, then encode and wrap in BytesIO.
    pdf_data = pdf.output(dest='S')
    if isinstance(pdf_data, str):
        pdf_bytes = pdf_data.encode('latin-1')
    else:
        pdf_bytes = pdf_data
    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    try:
        db = SessionLocal()
        log_audit(db, user=current_user.email, action='export_pdf', extra={'session_id': session_id})
    except Exception:
        pass
    return StreamingResponse(buf, media_type='application/pdf', headers={
        'Content-Disposition': f'attachment; filename=session_{session_id}.pdf'
    })


@app.get('/tts/{session_id}')
async def tts(session_id: str, current_user: models.User = Depends(get_current_user)):
    db = SessionLocal()
    entries = db.query(models.ChatEntry).filter(models.ChatEntry.session_id == session_id).order_by(models.ChatEntry.timestamp).all()
    if not entries:
        raise HTTPException(status_code=404, detail='Session not found')

    text = ''
    for e in entries:
        text += f"Question: {e.query}\nAnswer: {e.answer}\n\n"

    # generate TTS
    tts = gTTS(text=text, lang='en')
    outbuf = io.BytesIO()
    tts.write_to_fp(outbuf)
    outbuf.seek(0)
    try:
        db = SessionLocal()
        log_audit(db, user=current_user.email, action='tts', extra={'session_id': session_id})
    except Exception:
        pass
    return StreamingResponse(outbuf, media_type='audio/mpeg', headers={
        'Content-Disposition': f'attachment; filename=session_{session_id}.mp3'
    })

@app.post("/query")
async def query_endpoint(request: QueryRequest, current_user: models.User = Depends(get_current_user)):
    global vector_store
    if vector_store is None:
        # try to load existing simple index on-demand (no ML deps)
        vector_store = build_index.load_index_if_exists()
        if vector_store is None:
            # last resort: try to build simple index (fast)
            try:
                vector_store = build_index.build_and_save_index()
            except Exception as ie:
                print(f"Index build/load failed: {ie}")
                vector_store = {}
    try:
        db = SessionLocal()
        # pass language from request if provided
        lang = getattr(request, 'language', 'en') if hasattr(request, 'language') else 'en'
        result = queryEngine.query(request.query, vector_store, db=db, language=lang)
        # log the search action
        try:
            log_audit(db, user=current_user.email, action='search', extra={'query': request.query, 'session_id': result.get('session_id')})
        except Exception:
            pass
        # result has keys: answer, sources, gps, session_id
        return {
            "answer": result['answer'],
            "sources": result.get('sources', []),
            "gps": result.get('gps', []),
            "session_id": result.get('session_id')
        }
    except Exception as e:
        # Return a safe, structured response instead of 500 so frontend doesn't break
        print(f"Query error: {str(e)}")
        return {
            "answer": f"Search failed internally: {str(e)}",
            "sources": [],
            "gps": [],
            "session_id": None
        }

# Signup endpoint
@app.post("/signup", response_model=schemas.UserOut)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Generate salt and hash the password
    salt = utils.generate_salt()
    hashed_pwd = utils.hash_password(user.password, salt)
    
    # Create new user record without returning salt in response
    new_user = models.User(
        name=user.name,
        email=user.email,
        hashed_password=hashed_pwd,
        salt=salt
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


# Login endpoint
@app.post("/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    print(f"Login attempt for email: {user.email}")
    try:
        stored_user = db.query(models.User).filter(models.User.email == user.email).first()
        if not stored_user:
            print(f"User not found: {user.email}")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        print(f"Found user: {stored_user.email}")
        print(f"Verifying password...")
        
        valid = utils.verify_password(stored_user.hashed_password, stored_user.salt, user.password)
        if not valid:
            print("Password verification failed")
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        print("Password verified successfully")
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": stored_user.email}, expires_delta=access_token_expires
        )
        
        return {
            "token": access_token,
            "user": {
                "id": stored_user.id,
                "name": stored_user.name,
                "email": stored_user.email,
                "role": "user"  # Add role field for frontend
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
    
    return {
        "token": access_token,
        "user": {
            "id": stored_user.id,
            "name": stored_user.name,
            "email": stored_user.email,
            "role": "user"  # Add role field for frontend
        }
    }

# Logout endpoint
@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"msg": "Logged out"}
