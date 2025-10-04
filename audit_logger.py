"""
Enhanced Audit Logging Utility
Provides comprehensive activity tracking with security analysis and automated risk assessment
"""

import time
import json
import uuid
import requests
from datetime import datetime
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi import Request
import models


class AuditLogger:
    """Enhanced audit logger with security analysis and automated risk assessment"""
    
    def __init__(self, db: Session):
        self.db = db
        
    def log_activity(
        self,
        user: str,
        action: str,
        request: Optional[Request] = None,
        extra: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        resource_affected: Optional[str] = None,
        outcome: str = 'success',
        start_time: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Log comprehensive user activity with automatic risk assessment
        
        Args:
            user: User email/identifier
            action: Action performed (e.g., 'search', 'upload', 'export')
            request: FastAPI request object for IP/User-Agent extraction
            extra: Additional data specific to action
            session_id: Session identifier
            resource_affected: Resource affected by action (filename, case_id, etc.)
            outcome: Action outcome (success, failure, error)
            start_time: Start time for duration calculation
            metadata: Additional metadata for risk assessment
            
        Returns:
            Audit log entry ID
        """
        try:
            # Extract request information
            ip_address = self._extract_ip_address(request)
            user_agent = self._extract_user_agent(request)
            
            # Calculate duration if start time provided
            duration_ms = int((time.time() - start_time) * 1000) if start_time else None
            
            # Assess risk and severity
            severity, risk_score = self._assess_risk_level(action, user, extra, metadata)
            
            # Get geolocation (if IP available)
            geo_location = self._get_geo_location(ip_address) if ip_address else None
            
            # Create audit log entry
            audit_entry = models.AuditLog(
                user=user,
                action=action,
                extra=extra or {},
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                resource_affected=resource_affected,
                outcome=outcome,
                severity=severity,
                risk_score=risk_score,
                geo_location=geo_location,
                duration_ms=duration_ms
            )
            
            self.db.add(audit_entry)
            self.db.commit()
            self.db.refresh(audit_entry)
            
            # Check for suspicious patterns
            self._detect_suspicious_activity(user, ip_address, action)
            
            return audit_entry.id
            
        except Exception as e:
            print(f'Failed to log audit activity: {e}')
            # Don't raise exception to avoid breaking main functionality
            return 0
    
    def _extract_ip_address(self, request: Optional[Request]) -> Optional[str]:
        """Extract real IP address considering proxies"""
        if not request:
            return None
            
        # Check for forwarded headers first
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
            
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
            
        # Fallback to direct client IP
        if hasattr(request, 'client') and request.client:
            return request.client.host
            
        return None
    
    def _extract_user_agent(self, request: Optional[Request]) -> Optional[str]:
        """Extract user agent string"""
        if not request:
            return None
        return request.headers.get('User-Agent', '')[:500]  # Limit length
    
    def _assess_risk_level(self, action: str, user: str, extra: Optional[Dict], metadata: Optional[Dict]) -> tuple[str, int]:
        """
        Automatically assess risk level and severity based on action and context
        Returns: (severity, risk_score)
        """
        base_scores = {
            'login': (20, 'low'),
            'search': (10, 'low'),
            'upload': (40, 'medium'),
            'export': (60, 'high'),
            'delete': (80, 'high'),
            'rebuild_index': (70, 'high'),
            'admin_action': (90, 'critical'),
            'bulk_export': (85, 'high'),
            'sensitive_search': (75, 'high'),
            'payment_view': (90, 'critical')
        }
        
        action_lower = action.lower()
        base_risk, base_severity = base_scores.get(action_lower, (30, 'medium'))
        
        # Adjust based on context
        risk_adjustments = []
        
        # High-volume activity
        if extra and isinstance(extra, dict):
            file_count = extra.get('file_count', 0)
            if file_count > 10:
                risk_adjustments.append(20)
                base_severity = 'high'
            
            # Large file uploads
            total_size = extra.get('total_size_mb', 0)
            if total_size > 100:  # 100MB
                risk_adjustments.append(25)
                base_severity = 'high'
        
        # Admin user permissions
        if 'admin' in user.lower():
            risk_adjustments.append(10)
            if 'delete' in action or 'export' in action:
                base_severity = 'critical'
        
        # Calculate final risk score (max 100)
        final_risk = min(100, base_risk + sum(risk_adjustments))
        
        return base_severity, final_risk
    
    def _get_geo_location(self, ip_address: str) -> Optional[str]:
        """Get approximate geolocation from IP address"""
        try:
            # Using a free IP geolocation service
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('country', '')
                    city = data.get('city', '')
                    return f"{city}, {country}" if city else country
        except:
            pass
        return None
    
    def _detect_suspicious_activity(self, user: str, ip_address: Optional[str], action: str):
        """Detect and alert on suspicious activity patterns"""
        try:
            # Check for rapid repeated actions
            recent_count = self.db.execute(
                text("""
                    SELECT COUNT(*) FROM audit_logs 
                    WHERE user = :user AND timestamp > NOW() - INTERVAL '5 minutes'
                """),
                {'user': user}
            ).scalar()
            
            if recent_count > 10:  # More than 10 actions in 5 minutes
                self._create_alert('RAPID_ACTIVITY', {
                    'user': user,
                    'action_count': recent_count,
                    'recent_action': action
                })
            
            # Check for multiple IP addresses for same user in short time
            if ip_address:
                distinct_ips = self.db.execute(
                    text("""
                        SELECT COUNT(DISTINCT ip_address) FROM audit_logs 
                        WHERE user = :user AND timestamp > NOW() - INTERVAL '1 hour'
                        AND ip_address IS NOT NULL
                    """),
                    {'user': user}
                ).scalar()
                
                if distinct_ips > 3:  # User from more than 3 IPs in 1 hour
                    self._create_alert('MULTIPLE_IPS', {
                        'user': user,
                        'ip_count': distinct_ips,
                        'current_ip': ip_address
                    })
                    
        except Exception as e:
            print(f'Error detecting suspicious activity: {e}')
    
    def _create_alert(self, alert_type: str, data: Dict[str, Any]):
        """Create security alert for suspicious activity"""
        # In a production environment, this would:
        # 1. Log to security monitoring system
        # 2. Send notifications to administrators
        # 3. Potentially trigger automated responses
        
        alert_entry = models.AuditLog(
            user=data.get('user', 'SYSTEM'),
            action=f'SECURITY_ALERT:{alert_type}',
            extra=data,
            outcome='alert',
            severity='high',
            risk_score=95,
            resource_affected='SECURITY_MONITORING'
        )
        
        try:
            self.db.add(alert_entry)
            self.db.commit()
            print(f'SECURITY ALERT: {alert_type} - {data}')
        except Exception as e:
            print(f'Failed to create security alert: {e}')
    
    def get_user_activity_summary(self, user: str, days: int = 7) -> Dict[str, Any]:
        """Get comprehensive activity summary for user"""
        try:
            start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            start_date = start_date.replace(day=start_date.day - days)
            
            # Activity counts by type
            activity_counts = self.db.execute(
                text("""
                    SELECT action, COUNT(*) as count, AVG(duration_ms) as avg_duration, MAX(severity) as peak_severity
                    FROM audit_logs 
                    WHERE user = :user AND timestamp >= :start_date
                    GROUP BY action
                    ORDER BY count DESC
                """),
                {'user': user, 'start_date': start_date}
            ).fetchall()
            
            # Risk overview
            risk_stats = self.db.execute(
                text("""
                    SELECT 
                        AVG(risk_score) as avg_risk,
                        MAX(risk_score) as max_risk,
                        COUNT(CASE WHEN risk_score > 70 THEN 1 END) as high_risk_count
                    FROM audit_logs 
                    WHERE user = :user AND timestamp >= :start_date
                """),
                {'user': user, 'start_date': start_date}
            ).fetchone()
            
            # Recent IPs
            recent_ips = self.db.execute(
                text("""
                    SELECT DISTINCT ip_address, geo_location, COUNT(*) as access_count,
                           MAX(timestamp) as last_access
                    FROM audit_logs 
                    WHERE user = :user AND timestamp >= :start_date AND ip_address IS NOT NULL
                    GROUP BY ip_address, geo_location
                    ORDER BY last_access DESC
                    LIMIT 5
                """),
                {'user': user, 'start_date': start_date}
            ).fetchall()
            
            return {
                'user': user,
                'period_days': days,
                'activity_summary': [
                    {'action': row.action, 'count': row.count, 
                     'avg_duration_ms': row.avg_duration, 'peak_severity': row.peak_severity}
                    for row in activity_counts
                ],
                'risk_overview': {
                    'avg_risk_score': risk_stats.avg_risk,
                    'max_risk_score': risk_stats.max_risk,
                    'high_risk_actions': risk_stats.high_risk_count
                },
                'recent_access_points': [
                    {'ip': row.ip_address, 'location': row.geo_location, 
                     'access_count': row.access_count, 'last_access': row.last_access}
                    for row in recent_ips
                ]
            }
            
        except Exception as e:
            print(f'Error generating activity summary: {e}')
            return {'error': str(e)}
    
    def get_security_dashboard_data(self) -> Dict[str, Any]:
        """Get data for security monitoring dashboard"""
        try:
            # High-risk activities in last 24 hours
            high_risk_activities = self.db.execute(
                text("""
                    SELECT user, action, COUNT(*) as count, MAX(risk_score) as max_risk,
                           ARRAY_AGG(DISTINCT ip_address) as ip_addresses
                    FROM audit_logs 
                    WHERE timestamp > NOW() - INTERVAL '24 hours' 
                    AND risk_score > 70
                    GROUP BY user, action
                    ORDER BY max_risk DESC, count DESC
                    LIMIT 20
                """)
            ).fetchall()
            
            # Active users
            active_users = self.db.execute(
                text("""
                    SELECT user, COUNT(*) as activity_count, MAX(timestamp) as last_activity,
                           COUNT(DISTINCT ip_address) as ip_diversity
                    FROM audit_logs 
                    WHERE timestamp > NOW() - INTERVAL '24 hours'
                    GROUP BY user
                    ORDER BY activity_count DESC
                    LIMIT 15
                """)
            ).fetchall()
            
            # Security alerts
            security_alerts = self.db.execute(
                text("""
                    SELECT action, COUNT(*) as alert_count, MAX(risk_score) as severity
                    FROM audit_logs 
                    WHERE timestamp > NOW() - INTERVAL '24 hours' 
                    AND action LIKE 'SECURITY_ALERT:%'
                    GROUP BY action
                    ORDER BY alert_count DESC
                """)
            ).fetchall()
            
            return {
                'high_risk_activities': [
                    {'user': row.user, 'action': row.action, 'count': row.count, 
                     'max_risk': row.max_risk, 'ip_addresses': row.ip_addresses}
                    for row in high_risk_activities
                ],
                'active_users': [
                    {'user': row.user, 'activity_count': row.activity_count, 
                     'last_activity': row.last_activity, 'ip_diversity': row.ip_diversity}
                    for row in active_users
                ],
                'security_alerts': [
                    {'alert_type': row.action.replace('SECURITY_ALERT:', ''), 
                     'count': row.alert_count, 'severity': row.severity}
                    for row in security_alerts
                ]
            }
            
        except Exception as e:
            print(f'Error generating security dashboard data: {e}')
            return {'error': str(e)}


# Convenience function for easy integration
def log_activity_comprehensive(
    db: Session,
    user: str,
    action: str,
    request: Optional[Request] = None,
    **kwargs
) -> int:
    """Enhanced logging function with automatic context extraction"""
    logger = AuditLogger(db)
    return logger.log_activity(user, action, request, **kwargs)
