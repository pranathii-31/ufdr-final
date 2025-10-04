from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    
    # Relationships
    files = relationship("UploadedFile", back_populates="user")


class UploadedFile(Base):
    __tablename__ = 'uploaded_files'
    id = Column(String, primary_key=True, index=True)
    original_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    size = Column(Integer, nullable=False)
    upload_time = Column(DateTime(timezone=True), server_default=func.now())
    type = Column(String, nullable=False)
    processed = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="files")


class ChatEntry(Base):
    __tablename__ = 'chat_entries'
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, index=True)
    timestamp = Column(Integer)
    query = Column(Text)
    answer = Column(Text)
    sources = Column(JSON)


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True, index=True)
    user = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    extra = Column(JSON)
    ip_address = Column(String(45), index=True)  # IPv6 support
    user_agent = Column(Text)
    session_id = Column(String(255), index=True)
    resource_affected = Column(String(255), index=True)  # file, case_id, etc.
    outcome = Column(String(50), index=True)  # success, failure, error
    severity = Column(String(20), default='medium', index=True)  # low, medium, high, critical
    risk_score = Column(Integer, default=0, index=True)  # 0-100 risk assessment
    geo_location = Column(String(255))  # Country/city if IP geolocation available
    duration_ms = Column(Integer)  # Time taken for action
