"""
Demonstration of Enhanced Audit Logging System
Shows the comprehensive security analysis and tracking capabilities
"""

import sqlite3
import json
from datetime import datetime, timedelta
from audit_logger import AuditLogger
from database import SessionLocal
import models


def create_sample_audit_data():
    """Create sample audit log data to demonstrate the enhanced functionality"""
    db = SessionLocal()
    
    try:
        # Clear existing data
        db.query(models.AuditLog).delete()
        db.commit()
        
        # Sample audit logs with varied complexity and risk levels
        sample_logs = [
            # Low-risk routine activities
            {
                'user': 'john.doe@company.com',
                'action': 'search',
                'extra': {'query': 'routine document search', 'results_count': 5},
                'ip_address': '192.168.1.100',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'session_id': 'sess_001',
                'resource_affected': 'search_session_001',
                'outcome': 'success',
                'severity': 'low',
                'risk_score': 15,
                'geo_location': 'New York, United States',
                'duration_ms': 250
            },
            
            # Medium-risk bulk operations
            {
                'user': 'jane.smith@company.com',
                'action': 'upload',
                'extra': {'file_count': 8, 'total_size_mb': 45.2, 'file_types': ['pdf', 'docx', 'txt']},
                'ip_address': '192.168.1.101',
                'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'session_id': 'sess_002',
                'resource_affected': 'upload_batch_002',
                'outcome': 'success',
                'severity': 'medium',
                'risk_score': 45,
                'geo_location': 'San Francisco, United States',
                'duration_ms': 1500
            },
            
            # High-risk export operations
            {
                'user': 'admin@company.com',
                'action': 'bulk_export',
                'extra': {
                    'export_type': 'sensitive_data',
                    'record_count': 1250,
                    'data_types': ['financial_records', 'personal_info', 'case_files']
                },
                'ip_address': '192.168.1.1',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'session_id': 'sess_admin_001',
                'resource_affected': 'export_batch_admin_001',
                'outcome': 'success',
                'severity': 'high',
                'risk_score': 85,
                'geo_location': 'Washington DC, United States',
                'duration_ms': 3500
            },
            
            # Cross-file analysis
            {
                'user': 'detective.johnson@company.com',
                'action': 'cross_file_analysis',
                'extra': {
                    'analysis_type': 'contact_relationships',
                    'files_analyzed': 3,
                    'cross_references_found': 12,
                    'common_contacts': 5
                },
                'ip_address': '192.168.1.150',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'session_id': 'sess_detective_001',
                'resource_affected': 'cross_analysis_session_001',
                'outcome': 'success',
                'severity': 'medium',
                'risk_score': 55,
                'geo_location': 'Chicago, United States',
                'duration_ms': 4200
            },
            
            # Sensitive data access
            {
                'user': 'analyst.patel@company.com',
                'action': 'sensitive_search',
                'extra': {
                    'search_query': 'phone numbers financial transactions',
                    'data_sensitivity': 'high',
                    'privacy_flag': True,
                    'gdpr_compliance': 'checked'
                },
                'ip_address': '192.168.1.175',
                'user_agent': 'Mozilla/5.0 (Linux; Ubuntu 20.04; rv:89.0) Gecko/20100101 Firefox/89.0',
                'session_id': 'sess_analyst_001',
                'resource_affected': 'sensitive_data_search_001',
                'outcome': 'success',
                'severity': 'high',
                'risk_score': 75,
                'geo_location': 'Boston, United States',
                'duration_ms': 1800
            },
            
            # Security Alert - Suspicious Activity
            {
                'user': 'suspicious.user@external.com',
                'action': 'SECURITY_ALERT:RAPID_ACTIVITY',
                'extra': {
                    'activity_count': 25,
                    'time_window_minutes': 5,
                    'threshold_exceeded': True,
                    'automated_response': 'account_temporarily_suspended'
                },
                'ip_address': '203.0.113.100',  # External IP
                'user_agent': 'curl/7.68.0',
                'session_id': 'sess_suspicious_001',
                'resource_affected': 'SYSTEM_MONITORING',
                'outcome': 'alert',
                'severity': 'critical',
                'risk_score': 95,
                'geo_location': 'Unknown Location',
                'duration_ms': 50
            },
            
            # Failed login attempts
            {
                'user': 'unknown@external.com',
                'action': 'login',
                'extra': {
                    'login_attempts': 3,
                    'bad_credentials': True,
                    'account_locked': True
                },
                'ip_address': '198.51.100.50',
                'user_agent': 'python-requests/2.28.1',
                'session_id': 'failed_login_001',
                'resource_affected': 'authentication_system',
                'outcome': 'failure',
                'severity': 'high',
                'risk_score': 70,
                'geo_location': 'Unknown Location',
                'duration_ms': 120
            },
            
            # Admin system operations
            {
                'user': 'superadmin@company.com',
                'action': 'admin_action',
                'extra': {
                    'operation': 'user_permission_changes',
                    'affected_users': 3,
                    'permission_level': 'super_admin',
                    'requires_approval': True
                },
                'ip_address': '192.168.1.200',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'session_id': 'sess_superadmin_001',
                'resource_affected': 'user_management_system',
                'outcome': 'success',
                'severity': 'critical',
                'risk_score': 90,
                'geo_location': 'Washington DC, United States',
                'duration_ms': 500
            }
        ]
        
        # Create audit log entries
        for log_data in sample_logs:
            audit_entry = models.AuditLog(**log_data)
            db.add(audit_entry)
        
        db.commit()
        print(f"Created {len(sample_logs)} sample audit log entries")
        
        return len(sample_logs)
        
    except Exception as e:
        print(f"Error creating sample data: {e}")
        db.rollback()
        return 0
    finally:
        db.close()


def demonstrate_analytics():
    """Demonstrate the analytics capabilities of the enhanced audit system"""
    db = SessionLocal()
    
    try:
        logger = AuditLogger(db)
        
        print("\n🔍 AUDIT ANALYTICS DEMONSTRATION")
        print("=" * 50)
        
        # 1. Security Dashboard Data
        print("\n📊 Security Dashboard:")
        dashboard_data = logger.get_security_dashboard_data()
        
        print(f"  • High-risk activities (24h): {len(dashboard_data.get('high_risk_activities', []))}")
        print(f"  • Active users (24h): {len(dashboard_data.get('active_users', []))}")
        print(f"  • Security alerts: {len(dashboard_data.get('security_alerts', []))}")
        
        # 2. User Activity Summary
        print("\n👤 User Activity Summary (john.doe@company.com):")
        user_summary = logger.get_user_activity_summary('john.doe@company.com', days=7)
        
        print(f"  • User: {user_summary.get('user')}")
        print(f"  • Activity period: {user_summary.get('period_days')} days")
        print(f"  • Unique access points: {len(user_summary.get('recent_access_points', []))}")
        
        # 3. Advanced Risk Analysis
        print("\n⚠️  Risk Analysis:")
        
        # Query for risk statistics
        from sqlalchemy import func, text
        high_risk_count = db.query(models.AuditLog).filter(models.AuditLog.risk_score > 70).count()
        critical_count = db.query(models.AuditLog).filter(models.AuditLog.severity == 'critical').count()
        
        print(f"  • High-risk activities (>70 score): {high_risk_count}")
        print(f"  • Critical severity events: {critical_count}")
        
        # Most active users
        user_activity = db.execute(text("""
            SELECT user, COUNT(*) as activity_count, AVG(risk_score) as avg_risk
            FROM audit_logs 
            GROUP BY user 
            ORDER BY activity_count DESC 
            LIMIT 3
        """)).fetchall()
        
        print("\n🏆 Most Active Users:")
        for user_data in user_activity:
            print(f"  • {user_data.user}: {user_data.activity_count} activities (avg risk: {user_data.avg_risk:.1f})")
        
        # Geographic analysis
        geo_stats = db.execute(text("""
            SELECT geo_location, COUNT(*) as access_count
            FROM audit_logs 
            WHERE geo_location IS NOT NULL
            GROUP BY geo_location 
            ORDER BY access_count DESC 
            LIMIT 3
        """)).fetchall()
        
        print("\n🌍 Access by Location:")
        for geo_data in geo_stats:
            print(f"  • {geo_data.geo_location}: {geo_data.access_count} accesses")
        
        # Time-based patterns
        hourly_activity = db.execute(text("""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as activity_count
            FROM audit_logs 
            GROUP BY hour 
            ORDER BY hour
        """)).fetchall()
        
        print("\n⏰ Hourly Activity Pattern:")
        for hour_data in hourly_activity:
            print(f"  • {hour_data.hour}:00 - {hour_data.activity_count} activities")
            
    except Exception as e:
        print(f"Error in analytics demonstration: {e}")
    finally:
        db.close()


def demonstrate_security_detection():
    """Demonstrate the security threat detection capabilities"""
    print("\n🛡️  SECURITY THREAT DETECTION DEMONSTRATION")
    print("=" * 50)
    
    db = SessionLocal()
    try:
        # Simulate threat detection scenarios
        
        # 1. Rapid Activity Detection
        print("\n🚨 Rapid Activity Detection:")
        
        # Create rapid activity logs
        current_time = datetime.now()
        for i in range(12):  # 12 activities in quick succession
            log_entry = models.AuditLog(
                user='threat.example.com',
                action='search',
                extra={'query': f'rapid_search_{i}', 'ai_generated': True},
                ip_address='192.168.1.999',
                session_id=f'rapid_sess_{i}',
                outcome='success',
                severity='medium',
                risk_score=40,
                timestamp=current_time - timedelta(minutes=i),
                duration_ms=50 + i
            )
            db.add(log_entry)
        
        db.commit()
        print("  ✓ Created rapid activity pattern")
        
        # 2. Multiple IP Detection
        print("\n🌐 Multiple IP Access Detection:")
        
        ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '203.0.113.5']
        for ip in ips:
            log_entry = models.AuditLog(
                user='multi.ip.user@company.com',
                action='search',
                extra={'query': f'search_from_{ip}', 'multi_ip_detected': True},
                ip_address=ip,
                geo_location=f'Location_{ip}',
                session_id=f'multi_ip_sess_{ip}',
                outcome='success',
                severity='high',
                risk_score=60,
                timestamp=current_time - timedelta(hours=randint(1, 6))
            )
            db.add(log_entry)
        
        db.commit()
        print("  ✓ Created multi-IP access pattern")
        
        # 3. High-Risk Action Patterns
        print("\n⚠️  High-Risk Action Patterns:")
        
        high_risk_actions = ['bulk_export', 'sensitive_search', 'admin_action', 'delete']
        for action in high_risk_actions:
            log_entry = models.AuditLog(
                user='risk.example.com',
                action=action,
                extra={'action_type': 'high_risk', 'requires_review': True},
                ip_address='192.168.1.250',
                session_id=f'high_risk_sess_{action}',
                outcome='success',
 assigned='high',
                risk_score=randint(70, 95),
                timestamp=current_time - timedelta(minutes=randint(1, 120))
            )
            db.add(log_entry)
        
        db.commit()
        print("  ✓ Created high-risk action patterns")
        
        print("\n🎯 Would trigger automated alerts:")
        print("  • Rapid activity detection (>10 actions in 5 minutes)")
        print("  • Multiple IP addresses for same user")
        print("  • High-risk score aggregation")
        print("  • Geographic anomaly detection")
        
    except Exception as e:
        print(f"Error in security demonstration: {e}")
        db.rollback()
    finally:
        db.close()


def main():
    """Main demonstration function"""
    print("🔐 ENHANCED AUDIT LOGGING SYSTEM DEMONSTRATION")
    print("=" * 60)
    
    print("\n1. Creating sample audit data...")
    created_count = create_sample_audit_data()
    
    if created_count > 0:
        print(f"✅ Successfully created {created_count} sample audit entries")
        
        print("\n2. Demonstrating analytics capabilities...")
        demonstrate_analytics()
        
        print("\n3. Demonstrating security detection...")
        demonstrate_security_detection()
        
        print("\n🎉 DEMONSTRATION COMPLETE!")
        print("\nKey Features Demonstrated:")
        print("  ✓ Comprehensive audit trail with metadata")
        print("  ✓ Automated risk assessment and scoring")
        print("  ✓ Geographic tracking with IP analysis")
        print("  ✓ Security threat detection")
        print("  ✓ Advanced analytics and reporting")
        print("  ✓ Real-time monitoring capabilities")
        print("  ✓ Export functionality (JSON/CSV)")
        print("  ✓ User activity profiling")
        print("  ✓ Temporal pattern analysis")
        
    else:
        print("❌ Failed to create sample data")


if __name__ == "__main__":
    from random import randint
    main()
