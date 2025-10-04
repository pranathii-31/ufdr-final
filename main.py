from fastapi import FastAPI, HTTPException, Depends, status, Response, UploadFile, File, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
import models, schemas, schemas_audit, schemas_share, utils
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


def log_audit(db, user: str, action: str, extra: dict | None = None, request: Request = None):
    """Enhanced audit logging with comprehensive tracking"""
    try:
        from audit_logger import log_activity_comprehensive
        log_activity_comprehensive(
            db=db, 
            user=user, 
            action=action, 
            request=request,
            extra=extra or {}
        )
    except Exception as e:
        print('Failed to log audit', e)
        # Fallback to simple logging
        try:
            entry = models.AuditLog(user=user, action=action, extra=extra or {})
            db.add(entry)
            db.commit()
            print('Used fallback audit logging')
        except Exception as e2:
            print('Fallback audit logging also failed:', e2)



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


@app.get('/audit-logs', response_model=schemas_audit.AuditLogResponse)
async def get_audit_logs(
    user: str | None = None, 
    action: str | None = None, 
    severity: str | None = None,
    risk_score_min: int | None = None,
    outcome: str | None = None,
    page: int = 1, 
    page_size: int = 50, 
    current_user: models.User = Depends(get_current_user)
):
    """Enhanced audit logs with comprehensive filtering and security analysis"""
    db = SessionLocal()
    try:
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        
        q = db.query(models.AuditLog)
        
        # Apply filters
        if user:
            q = q.filter(models.AuditLog.user == user)
        if action:
            q = q.filter(models.AuditLog.action == action)
        if severity:
            q = q.filter(models.AuditLog.severity == severity)
        if risk_score_min:
            q = q.filter(models.AuditLog.risk_score >= risk_score_min)
        if outcome:
            q = q.filter(models.AuditLog.outcome == outcome)
            
        total = q.count()
        logs = q.order_by(models.AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        
        # Convert to enhanced format
        items = []
        for log in logs:
            items.append({
                "id": log.id,
                "user": log.user,
                "action": log.action,
                "timestamp": log.timestamp,
                "extra": log.extra,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "session_id": log.session_id,
                "resource_affected": log.resource_affected,
                "outcome": log.outcome,
                "severity": log.severity,
                "risk_score": log.risk_score,
                "geo_location": log.geo_location,
                "duration_ms": log.duration_ms
            })
        
        # Create filter summary
        filters_applied = {
            "user": user,
            "action": action,
            "severity": severity,
            "risk_score_min": risk_score_min,
            "outcome": outcome,
            "start_date": None,
            "end_date": None,
            "ip_address": None
        }
        
        return {
            "total": total, 
            "page": page, 
            "page_size": page_size, 
            "items": items,
            "filters_applied": filters_applied
        }
    except Exception as e:
        db.close()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get('/audit-logs/user/{user_email}/activity-summary', response_model=schemas_audit.UserActivitySummary)
async def get_user_activity_summary(
    user_email: str, 
    days: int = 7,
    current_user: models.User = Depends(get_current_user)
):
    """Get comprehensive activity summary and risk profile for a user"""
    db = SessionLocal()
    try:
        from audit_logger import AuditLogger
        logger = AuditLogger(db)
        summary = logger.get_user_activity_summary(user_email, days)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get('/audit-logs/security-dashboard', response_model=schemas_audit.SecurityDashboardData)
async def get_security_dashboard(
    current_user: models.User = Depends(get_current_user)
):
    """Get security monitoring dashboard data"""
    db = SessionLocal()
    try:
        from audit_logger import AuditLogger
        logger = AuditLogger(db)
        dashboard_data = logger.get_security_dashboard_data()
        return dashboard_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.post('/audit-logs/export')
async def export_audit_logs(
    export_request: schemas_audit.AuditLogExportRequest,
    current_user: models.User = Depends(get_current_user)
):
    """Export audit logs in various formats with comprehensive filtering"""
    db = SessionLocal()
    try:
        from audit_logger import AuditLogger
        logger = AuditLogger(db)
        
        # Apply filters
        q = db.query(models.AuditLog)
        
        if export_request.filters.user:
            q = q.filter(models.AuditLog.user == export_request.filters.user)
        if export_request.filters.action:
            q = q.filter(models.AuditLog.action == export_request.filters.action)
        if export_request.filters.severity:
            q = q.filter(models.AuditLog.severity == export_request.filters.severity)
        if export_request.filters.risk_score_min:
            q = q.filter(models.AuditLog.risk_score >= export_request.filters.risk_score_min)
        if export_request.filters.outcome:
            q = q.filter(models.AuditLog.outcome == export_request.filters.outcome)
        
        logs = q.order_by(models.AuditLog.timestamp.desc()).all()
        
        if export_request.format == 'json':
            content = json.dumps([
                {
                    'id': log.id, 'user': log.user, 'action': log.action,
                    'timestamp': log.timestamp.isoformat(), 'extra': log.extra,
                    'ip_address': log.ip_address, 'geo_location': log.geo_location,
                    'severity': log.severity, 'risk_score': log.risk_score,
                    'outcome': log.outcome, 'duration_ms': log.duration_ms,
                    'resource_affected': log.resource_affected
                } for log in logs
            ], indent=2)
            
            return StreamingResponse(
                io.BytesIO(content.encode('utf-8')),
                media_type='application/json',
                headers={'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
            )
            
        elif export_request.format == 'csv':
            import csv
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            headers = ['ID', 'User', 'Action', 'Timestamp', 'IP Address', 'Geo Location', 
                      'Severity', 'Risk Score', 'Outcome', 'Duration (ms)', 'Resource Affected']
            writer.writerow(headers)
            
            # Write data
            for log in logs:
                writer.writerow([
                    log.id, log.user, log.action, log.timestamp.isoformat(),
                    log.ip_address, log.geo_location, log.severity, log.risk_score,
                    log.outcome, log.duration_ms, log.resource_affected
                ])
            
            csv_content = output.getvalue()
            return StreamingResponse(
                io.BytesIO(csv_content.encode('utf-8')),
                media_type='text/csv',
                headers={'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
            )
        
        else:
            raise HTTPException(status_code=400, detail='Unsupported export format')
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get('/audit-logs/stats')
async def get_audit_log_stats(
    days: int = 30,
    current_user: models.User = Depends(get_current_user)
):
    """Get comprehensive audit log statistics and analytics"""
    db = SessionLocal()
    try:
        from sqlalchemy import func, text
        
        # Basic stats
        total_logs = db.query(models.AuditLog).count()
        unique_users = db.query(func.count(func.distinct(models.AuditLog.user))).scalar()
        
        # Risk analysis
        high_risk_count = db.query(models.AuditLog).filter(models.AuditLog.risk_score > 70).count()
        avg_risk = db.query(func.avg(models.AuditLog.risk_score)).scalar() or 0
        
        # Most common actions
        common_actions = db.query(
            models.AuditLog.action,
            func.count(models.AuditLog.id).label('count')
        ).group_by(models.AuditLog.action).order_by(func.count(models.AuditLog.id).desc()).limit(10).all()
        
        # Security alerts count
        security_alerts = db.query(models.AuditLog).filter(
            models.AuditLog.action.like('SECURITY_ALERT:%')
        ).count()
        
        # Activity by severity
        severity_stats = db.query(
            models.AuditLog.severity,
            func.count(models.AuditLog.id).label('count'),
            func.avg(models.AuditLog.risk_score).label('avg_risk')
        ).group_by(models.AuditLog.severity).order_by(func.count(models.AuditLog.id).desc()).all()
        
        return {
            'total_logs': total_logs,
            'unique_users': unique_users,
            'high_risk_count': high_risk_count,
            'avg_risk_score': round(float(avg_risk), 2),
            'security_alerts_count': security_alerts,
            'period_days': days,
            'most_common_actions': [
                {'action': action, 'count': count} 
                for action, count in common_actions
            ],
            'severity_distribution': [
                {'severity': severity, 'count': count, 'avg_risk': float(avg_risk_value)}
                for severity, count, avg_risk_value in severity_stats
            ]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.post('/chat-history/{session_id}')
async def save_chat_message(session_id: str, msg: dict):
    db = SessionLocal()
    entry = models.ChatEntry(session_id=session_id, timestamp=int(time.time()), query=msg.get('query',''), answer=msg.get('answer',''), sources=msg.get('sources', []))
    db.add(entry)
    db.commit()
    return {"status": "ok"}


@app.post('/export-pdf')
async def export_pdf_full_history(request_data: schemas.PDFExportRequest, current_user: models.User = Depends(get_current_user)):
    """Export PDF with complete chat history from frontend"""
    chat_history = request_data.chat_history
    
    if not chat_history:
        raise HTTPException(status_code=400, detail='No chat history provided')
    
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Complete Chat History', ln=True)
        pdf.ln(8)
        
        pdf.set_font('Arial', size=12)
        
        for message in chat_history:
            # Add timestamp from session
            timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Format message based on type
            if message.get('type') == 'user':
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, 'User:', ln=True)
                pdf.set_font('Arial', size=12)
                # Safely handle text content
                text_content = str(message.get('text', ''))[:500]  # Limit length
                pdf.multi_cell(0, 8, text_content)
            else:
                pdf.set_font('Arial', 'B', 12) 
                pdf.cell(0, 8, 'Assistant:', ln=True)
                pdf.set_font('Arial', size=12)
                # Safely handle text content
                text_content = str(message.get('text', ''))[:500]  # Limit length
                pdf.multi_cell(0, 8, text_content)
                
                # Add sources count if available
                if message.get('results') and len(message.get('results', [])) > 0:
                    pdf.set_font('Arial', 'I', 10)
                    pdf.cell(0, 6, f'(Found {len(message.get("results", []))} relevant sources)', ln=True)
                    pdf.set_font('Arial', size=12)
            
            pdf.ln(8)
    except Exception as e:
        print(f"PDF generation error: {e}")
        # Fallback to simple text-based PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', size=12)
        pdf.cell(0, 10, 'Chat History Export', ln=True)
        pdf.ln(5)
        
        for i, message in enumerate(chat_history):
            pdf.cell(0, 8, f"Message {i+1}: {message.get('type', 'unknown')}", ln=True)
            text_content = str(message.get('text', ''))[:200]
            pdf.multi_cell(0, 6, text_content)
            pdf.ln(3)

    # Create PDF bytes
    pdf_data = pdf.output(dest='S')
    if isinstance(pdf_data, str):
        pdf_bytes = pdf_data.encode('latin-1')
    else:
        pdf_bytes = pdf_data
    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    
    # Log audit
    try:
        db = SessionLocal()
        log_audit(db, user=current_user.email, action='export_pdf', extra={'chat_history_count': len(chat_history)})
    except Exception:
        pass
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return StreamingResponse(buf, media_type='application/pdf', headers={
        'Content-Disposition': f'attachment; filename=complete_chat_history_{timestamp}.pdf'
    })

@app.get('/export-pdf/{session_id}')
async def export_pdf_session(session_id: str, current_user: models.User = Depends(get_current_user)):
    """Legacy endpoint - Export PDF for a specific session from database"""
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
        # Enhanced audit logging
        try:
            # Determine action type based on query content
            query_lower = request.query.lower()
            action_type = 'search'
            if any(word in query_lower for word in ['cross', 'compare', 'relationship', 'common', 'between']):
                action_type = 'cross_file_analysis'
            elif any(word in query_lower for word in ['phone', 'email', 'contact', 'device']):
                action_type = 'sensitive_search'
                
            log_audit(
                db=db, 
                user=current_user.email, 
                action=action_type,
                request=request,
                extra={
                    'query': request.query[:100],  # Truncate for storage
                    'query_length': len(request.query),
                    'session_id': result.get('session_id'),
                    'extracted_information': {
                        'contacts_count': len(result.get('contacts', [])),
                        'sources_count': len(result.get('sources', [])),
                        'phones_count': len(result.get('phones', []))
                    }
                },
                session_id=result.get('session_id'),
                resource_affected=f"search_session_{result.get('session_id', 'unknown')}"
            )
        except Exception as e:
            print(f'Audit logging failed: {e}')
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


# Sharing and Collaboration Endpoints
@app.post('/api/share/generate-link', response_model=schemas_share.ShareLinkResponse)
async def generate_share_link(
    request: schemas_share.ShareLinkRequest,
    current_user: models.User = Depends(get_current_user)
):
    """Generate a secure share link for collaboration"""
    try:
        # Generate unique share ID
        share_id = str(uuid.uuid4())
        
        # Calculate expiry date
        from datetime import timedelta
        expires_at = datetime.now() + timedelta(days=request.expiry_days)
        
        # Store share data (in production, use Redis or database)
        share_data = {
            'share_id': share_id,
            'data': request.data.dict(),
            'permissions': request.permissions,
            'expires_at': expires_at.isoformat(),
            'created_by': current_user.email,
            'created_at': datetime.now().isoformat(),
            'access_count': 0
        }
        
        # In production, store this in database
        # For now, we'll simulate with a simple in-memory store
        if not hasattr(app.state, 'share_links'):
            app.state.share_links = {}
        app.state.share_links[share_id] = share_data
        
        # Generate share link
        share_link = f"https://forenseek.com/share/{share_id}"
        
        # Log the sharing activity
        try:
            db = SessionLocal()
            log_audit(
                db=db,
                user=current_user.email,
                action='share_generated',
                extra={
                    'share_id': share_id,
                    'share_type': request.data.type,
                    'permissions': request.permissions,
                    'expiry_days': request.expiry_days
                }
            )
        except Exception as e:
            print(f"Failed to log share activity: {e}")
        
        return schemas_share.ShareLinkResponse(
            success=True,
            link=share_link,
            share_id=share_id,
            expires_at=expires_at,
            permissions=request.permissions
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate share link: {str(e)}")


@app.post('/api/share/send-email', response_model=schemas_share.EmailShareResponse)
async def send_email_share(
    request: schemas_share.EmailShareRequest,
    current_user: models.User = Depends(get_current_user)
):
    """Send share via email"""
    try:
        # In production, integrate with email service (SendGrid, AWS SES, etc.)
        # For now, simulate email sending
        
        recipients_sent = 0
        recipients_failed = 0
        
        for recipient in request.recipients:
            try:
                # Simulate email sending
                print(f"Email sent to {recipient}: {request.message}")
                recipients_sent += 1
            except Exception:
                recipients_failed += 1
        
        # Log the email sharing activity
        try:
            db = SessionLocal()
            log_audit(
                db=db,
                user=current_user.email,
                action='email_share_sent',
                extra={
                    'recipients': [str(r) for r in request.recipients],
                    'share_type': request.data.type,
                    'recipients_sent': recipients_sent,
                    'recipients_failed': recipients_failed
                }
            )
        except Exception as e:
            print(f"Failed to log email share activity: {e}")
        
        return schemas_share.EmailShareResponse(
            success=True,
            message=f"Email sent to {recipients_sent} recipients",
            recipients_sent=recipients_sent,
            recipients_failed=recipients_failed
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email share: {str(e)}")


@app.post('/api/share/generate-export')
async def generate_share_export(
    request: schemas_share.ExportShareRequest,
    current_user: models.User = Depends(get_current_user)
):
    """Generate export file for sharing"""
    try:
        if request.format == 'pdf':
            # Use existing PDF generation logic
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'FORENSEEK - Shared Data Export', ln=True)
            pdf.ln(8)
            
            # Add metadata
            pdf.set_font('Arial', size=12)
            pdf.cell(0, 8, f'Shared by: {current_user.email}', ln=True)
            pdf.cell(0, 8, f'Shared on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
            pdf.cell(0, 8, f'Data Type: {request.data.type}', ln=True)
            pdf.ln(5)
            
            # Add search query if available
            if request.data.query:
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, 'Search Query:', ln=True)
                pdf.set_font('Arial', size=12)
                pdf.multi_cell(0, 8, request.data.query)
                pdf.ln(5)
            
            # Add results
            if request.data.results:
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, f'Search Results ({len(request.data.results)} items):', ln=True)
                pdf.set_font('Arial', size=10)
                
                for i, result in enumerate(request.data.results[:20]):  # Limit to first 20 results
                    pdf.cell(0, 6, f"{i+1}. {str(result)[:100]}...", ln=True)
            
            # Add conversation if available
            if request.data.conversation:
                pdf.ln(5)
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 8, f'Conversation History ({len(request.data.conversation)} messages):', ln=True)
                pdf.set_font('Arial', size=10)
                
                for msg in request.data.conversation[-10:]:  # Last 10 messages
                    pdf.set_font('Arial', 'B', 10)
                    pdf.cell(0, 6, f"{msg.get('type', 'unknown').title()}:", ln=True)
                    pdf.set_font('Arial', size=10)
                    text_content = str(msg.get('text', ''))[:200]
                    pdf.multi_cell(0, 6, text_content)
                    pdf.ln(2)
            
            # Generate PDF bytes
            pdf_data = pdf.output(dest='S')
            if isinstance(pdf_data, str):
                pdf_bytes = pdf_data.encode('latin-1')
            else:
                pdf_bytes = pdf_data
            
            # Log the export sharing activity
            try:
                db = SessionLocal()
                log_audit(
                    db=db,
                    user=current_user.email,
                    action='export_share_generated',
                    extra={
                        'format': request.format,
                        'share_type': request.data.type,
                        'data_size': len(str(request.data.dict()))
                    }
                )
            except Exception as e:
                print(f"Failed to log export share activity: {e}")
            
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type='application/pdf',
                headers={
                    'Content-Disposition': f'attachment; filename=forenseek_share_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
                }
            )
        
        elif request.format == 'json':
            # Generate JSON export
            export_data = {
                'metadata': {
                    'shared_by': current_user.email,
                    'shared_at': datetime.now().isoformat(),
                    'data_type': request.data.type,
                    'export_format': 'json'
                },
                'data': request.data.dict()
            }
            
            json_content = json.dumps(export_data, indent=2)
            return StreamingResponse(
                io.BytesIO(json_content.encode('utf-8')),
                media_type='application/json',
                headers={
                    'Content-Disposition': f'attachment; filename=forenseek_share_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                }
            )
        
        else:
            raise HTTPException(status_code=400, detail='Unsupported export format')
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate export: {str(e)}")


@app.get('/api/share/{share_id}')
async def access_shared_content(share_id: str):
    """Access shared content via share link"""
    try:
        # In production, retrieve from database
        if not hasattr(app.state, 'share_links'):
            raise HTTPException(status_code=404, detail='Share not found')
        
        share_data = app.state.share_links.get(share_id)
        if not share_data:
            raise HTTPException(status_code=404, detail='Share not found')
        
        # Check if expired
        from datetime import datetime
        expires_at = datetime.fromisoformat(share_data['expires_at'])
        if datetime.now() > expires_at:
            raise HTTPException(status_code=410, detail='Share has expired')
        
        # Update access count
        share_data['access_count'] += 1
        
        # Log access
        try:
            db = SessionLocal()
            log_audit(
                db=db,
                user='anonymous',
                action='shared_content_accessed',
                extra={
                    'share_id': share_id,
                    'access_count': share_data['access_count']
                }
            )
        except Exception as e:
            print(f"Failed to log share access: {e}")
        
        return {
            'success': True,
            'data': share_data['data'],
            'permissions': share_data['permissions'],
            'created_by': share_data['created_by'],
            'created_at': share_data['created_at'],
            'access_count': share_data['access_count']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to access shared content: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
