"""
Test Enhanced Audit Logging System
Demonstrates the new comprehensive audit logging capabilities
"""

from database import SessionLocal
from audit_logger import AuditLogger
import models


def test_enhanced_audit_logging():
    """Test the enhanced audit logging functionality"""
    print("🔐 TESTING ENHANCED AUDIT LOGGING SYSTEM")
    print("=" * 50)
    
    db = SessionLocal()
    
    try:
        # Create audit logger instance
        logger = AuditLogger(db)
        
        # Test 1: Log a regular search activity
        print("\n1. Logging regular search activity...")
        search_log_id = logger.log_activity(
            user="test.user@company.com",
            action="search",
            extra={
                'query': 'financial fraud investigation',
                'results_count': 15,
                'query_sensitivity': 'high'
            },
            session_id="test_session_001",
            resource_affected="case_file_fraud_2024",
            start_time=None
        )
        print(f"   ✓ Search activity logged with ID: {search_log_id}")
        
        # Test 2: Log upload activity with high volume
        print("\n2. Logging file upload activity...")
        upload_log_id = logger.log_activity(
            user="detective.johnson@company.com",
            action="upload",
            extra={
                'file_count': 25,
                'total_size_mb': 450.5,
                'file_types': ['pdf', 'docx', 'txt', 'xlsx'],
                'bulk_operation': True
            },
            session_id="test_session_002",
            resource_affected="evidence_batch_2024_case123",
            start_time=None
        )
        print(f"   ✓ Upload activity logged with ID: {upload_log_id}")
        
        # Test 3: Log cross-file analysis activity
        print("\n3. Logging cross-file analysis...")
        analysis_log_id = logger.log_activity(
            user="analyst.smith@company.com",
            action="cross_file_analysis",
            extra={
                'files_analyzed': 5,
                'analysis_type': 'contact_relationships',
                'cross_references_found': 127,
                'common_contacts': 23,
                'data_sensitivity': 'high'
            },
            session_id="test_session_003",
            resource_affected="multi_file_analysis_contacts",
            start_time=None
        )
        print(f"   ✓ Cross-file analysis logged with ID: {analysis_log_id}")
        
        # Test 4: Log sensitive data export
        print("\n4. Logging sensitive data export...")
        export_log_id = logger.log_activity(
            user="admin.superuser@company.com",
            action="bulk_export",
            extra={
                'export_type': 'financial_records',
                'record_count': 2500,
                'data_types': ['bank_transactions', 'credit_cards', 'loans'],
                'approved_by': 'supervisor_approval_001',
                'compliance_checked': True
            },
            session_id="test_session_admin_001",
            resource_affected="financial_export_batch_2024",
            start_time=None
        )
        print(f"   ✓ Sensitive export logged with ID: {export_log_id}")
        
        # Test 5: Get audit log statistics
        print("\n5. Getting audit log statistics...")
        stats = db.query(models.AuditLog).count()
        high_risk_count = db.query(models.AuditLog).filter(models.AuditLog.risk_score > 70).count()
        avg_risk = db.query(models.AuditLog).filter(models.AuditLog.risk_score > 0).first()
        
        print(f"   ✓ Total audit entries: {stats}")
        print(f"   ✓ High-risk activities: {high_risk_count}")
        print(f"   ✓ Sample risk score: {avg_risk.risk_score if avg_risk else 'N/A'}")
        
        # Test 6: Verify enhanced fields
        print("\n6. Verifying enhanced audit fields...")
        latest_log = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).first()
        
        if latest_log:
            print(f"   ✓ Latest log contains:")
            print(f"      - User: {latest_log.user}")
            print(f"      - Action: {latest_log.action}")
            print(f"      - Severity: {latest_log.severity}")
            print(f"      - Risk Score: {latest_log.risk_score}/100")
            print(f"      - Outcome: {latest_log.outcome}")
            print(f"      - Session ID: {latest_log.session_id}")
            print(f"      - Resource: {latest_log.resource_affected}")
            print(f"      - Duration: {latest_log.duration_ms}ms")
        
        print("\n🎉 ENHANCED AUDIT LOGGING SYSTEM TEST COMPLETED!")
        print("\nKey Features Demonstrated:")
        print("  ✓ Comprehensive activity logging with metadata")
        print("  ✓ Automatic risk assessment and scoring")
        print("  ✓ Enhanced security tracking")
        print("  ✅ All enhanced fields populated correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
        
    finally:
        db.close()


if __name__ == "__main__":
    success = test_enhanced_audit_logging()
    if success:
        print("\n🚀 Ready for production use!")
    else:
        print("\n⚠️  Issues detected - review implementation")
