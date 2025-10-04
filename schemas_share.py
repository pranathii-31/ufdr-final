"""
Pydantic schemas for sharing and collaboration functionality
"""

from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime


class ShareData(BaseModel):
    """Data structure for sharing content"""
    type: str  # 'search_results', 'conversation', 'case_data'
    query: Optional[str] = None
    results: List[Dict[str, Any]] = []
    conversation: List[Dict[str, Any]] = []
    timestamp: str
    user: str
    metadata: Dict[str, Any] = {}


class ShareLinkRequest(BaseModel):
    """Request to generate a share link"""
    data: ShareData
    permissions: str = Field("view", pattern="^(view|comment|edit)$")
    expiry_days: int = Field(7, ge=0, le=365)
    message: Optional[str] = None


class ShareLinkResponse(BaseModel):
    """Response with generated share link"""
    success: bool
    link: str
    share_id: str
    expires_at: datetime
    permissions: str


class EmailShareRequest(BaseModel):
    """Request to share via email"""
    data: ShareData
    recipients: List[EmailStr]
    message: Optional[str] = None
    permissions: str = Field("view", pattern="^(view|comment|edit)$")


class EmailShareResponse(BaseModel):
    """Response for email share"""
    success: bool
    message: str
    recipients_sent: int
    recipients_failed: int


class ExportShareRequest(BaseModel):
    """Request to generate export for sharing"""
    data: ShareData
    format: str = Field("pdf", pattern="^(pdf|json|csv)$")
    include_metadata: bool = True


class ShareAccess(BaseModel):
    """Share access information"""
    share_id: str
    user_email: str
    permissions: str
    accessed_at: datetime
    ip_address: Optional[str] = None


class ShareStats(BaseModel):
    """Share statistics"""
    total_shares: int
    active_shares: int
    total_views: int
    most_shared_type: str
    recent_shares: List[Dict[str, Any]]
