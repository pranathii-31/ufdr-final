"""
Pydantic schemas for audit logging functionality
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class AuditLogFilter(BaseModel):
    """Filters for audit log queries"""
    user: Optional[str] = None
    action: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    severity: Optional[str] = None
    risk_score_min: Optional[int] = Field(None, ge=0, le=100)
    ip_address: Optional[str] = None
    outcome: Optional[str] = None


class AuditLogEntry(BaseModel):
    """Format for individual audit log entries"""
    id: int
    user: str
    action: str
    timestamp: datetime
    extra: Dict[str, Any]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    resource_affected: Optional[str] = None
    outcome: str
    severity: str
    risk_score: int
    geo_location: Optional[str] = None
    duration_ms: Optional[int] = None


class AuditLogResponse(BaseModel):
    """Response format for paginated audit logs"""
    total: int
    page: int
    page_size: int
    items: List[AuditLogEntry]
    filters_applied: AuditLogFilter


class UserActivitySummary(BaseModel):
    """Activity summary for a specific user"""
    user: str
    period_days: int
    activity_summary: List[Dict[str, Any]]
    risk_overview: Dict[str, Any]
    recent_access_points: List[Dict[str, Any]]


class SecurityDashboardData(BaseModel):
    """Security monitoring dashboard data"""
    high_risk_activities: List[Dict[str, Any]]
    active_users: List[Dict[str, Any]]
    security_alerts: List[Dict[str, Any]]


class AuditLogExportRequest(BaseModel):
    """Request format for exporting audit logs"""
    filters: AuditLogFilter
    format: str = Field("csv", pattern="^(csv|json|pdf)$")
    include_geo_data: bool = True


class RiskAssessmentRequest(BaseModel):
    """Request for manual risk assessment"""
    user: str
    action: str
    extra: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class RiskAssessmentResponse(BaseModel):
    """Response for risk assessment"""
    severity: str
    risk_score: int
    risk_factors: List[str]
    recommendations: List[str]


class AuditLogStats(BaseModel):
    """Audit log statistics"""
    total_logs: int
    unique_users: int
    high_risk_count: int
    avg_risk_score: float
    most_common_actions: List[Dict[str, Any]]
    security_alerts_count: int
    period: str
