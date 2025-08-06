"""
test_crud_security.py

Tests for CRUD operations with security enhancements.
Validates database operations, audit logging, and access control.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

from src.database import Base
from src.models import User, Rule, LogEntry, AuditLog
from src.security import get_password_hash
from src import crud, schemas

# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_crud_security.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def setup_database():
    """Set up test database"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session(setup_database):
    """Get database session for tests"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def test_user(db_session):
    """Create a test user"""
    user = User(
        username="test_user",
        email="test@example.com",
        hashed_password=get_password_hash("TestPass123!"),
        role="admin",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def test_rule(db_session):
    """Create a test rule"""
    rule = Rule(
        sensor_id="test_sensor",
        metric="motion",
        operator="==",
        threshold=0.0,
        target_topic="alerts/test",
        payload="TEST_ALERT"
    )
    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)
    return rule

class TestUserCRUD:
    """Test user CRUD operations"""
    
    def test_create_user(self, db_session):
        """Test user creation"""
        user_data = schemas.UserCreate(
            username="new_user",
            email="new@example.com",
            password="NewPass123!",
            role="viewer"
        )
        
        # Create user
        hashed_password = get_password_hash(user_data.password)
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            role=user_data.role
        )
        
        db_session.add(db_user)
        db_session.commit()
        db_session.refresh(db_user)
        
        assert db_user.id is not None
        assert db_user.username == "new_user"
        assert db_user.email == "new@example.com"
        assert db_user.role == "viewer"
        assert db_user.is_active == True
        assert db_user.hashed_password != user_data.password  # Should be hashed

    def test_get_user_by_username(self, db_session, test_user):
        """Test retrieving user by username"""
        user = db_session.query(User).filter(User.username == "test_user").first()
        assert user is not None
        assert user.username == "test_user"
        assert user.email == "test@example.com"

    def test_user_password_verification(self, db_session, test_user):
        """Test password verification"""
        from src.security import verify_password
        
        # Correct password should verify
        assert verify_password("TestPass123!", test_user.hashed_password) == True
        
        # Incorrect password should not verify
        assert verify_password("WrongPassword", test_user.hashed_password) == False

class TestRuleCRUDSecurity:
    """Test rule CRUD operations with security"""
    
    def test_get_matching_rules(self, db_session, test_rule):
        """Test getting matching rules function"""
        # Test the new get_matching_rules function
        matching_rules = crud.get_matching_rules(db_session, "test_sensor", "motion")
        assert len(matching_rules) == 1
        assert matching_rules[0].id == test_rule.id
        
        # Test with non-matching criteria
        no_match = crud.get_matching_rules(db_session, "nonexistent", "motion")
        assert len(no_match) == 0

    def test_create_rule_with_validation(self, db_session):
        """Test rule creation with input validation"""
        rule_data = schemas.RuleCreate(
            sensor_id="validated_sensor",
            metric="temperature",
            operator=">",
            threshold=25.0,
            target_topic="alerts/temperature",
            payload="HIGH_TEMPERATURE"
        )
        
        rule = crud.create_rule(db_session, rule_data)
        assert rule.id is not None
        assert rule.sensor_id == "validated_sensor"
        assert rule.metric == "temperature"
        assert rule.operator == ">"
        assert rule.threshold == 25.0

    def test_delete_rule_security(self, db_session, test_rule):
        """Test rule deletion with proper error handling"""
        # Delete existing rule
        result = crud.delete_rule(db_session, test_rule.id)
        assert "deleted successfully" in result["message"]
        
        # Verify rule is deleted
        deleted_rule = db_session.query(Rule).filter(Rule.id == test_rule.id).first()
        assert deleted_rule is None
        
        # Try to delete non-existent rule
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            crud.delete_rule(db_session, 999999)
        assert exc_info.value.status_code == 404

class TestLogEntrySecurity:
    """Test log entry operations with security"""
    
    def test_log_event_creation(self, db_session, test_rule):
        """Test creating log entries"""
        crud.log_event(
            db_session,
            rule_id=test_rule.id,
            sensor_id="test_sensor",
            metric="motion",
            value=0.0
        )
        
        # Check log entry was created
        log_entry = db_session.query(LogEntry).filter(
            LogEntry.rule_id == test_rule.id
        ).first()
        
        assert log_entry is not None
        assert log_entry.rule_id == test_rule.id
        assert log_entry.sensor_id == "test_sensor"
        assert log_entry.metric == "motion"
        assert log_entry.value == 0.0
        assert log_entry.triggered_at is not None

    def test_get_logs_with_filtering(self, db_session, test_rule):
        """Test getting logs with filtering"""
        # Create some log entries
        for i in range(5):
            crud.log_event(
                db_session,
                rule_id=test_rule.id,
                sensor_id=f"sensor_{i}",
                metric="motion",
                value=float(i)
            )
        
        # Test getting all logs
        all_logs = crud.get_logs(db_session)
        assert len(all_logs) == 5
        
        # Test filtering by rule_id
        filtered_logs = crud.get_logs(db_session, rule_id=test_rule.id)
        assert len(filtered_logs) == 5
        assert all(log.rule_id == test_rule.id for log in filtered_logs)

    def test_get_recent_logs(self, db_session, test_rule):
        """Test getting recent logs"""
        # Create log entries
        crud.log_event(
            db_session,
            rule_id=test_rule.id,
            sensor_id="recent_sensor",
            metric="motion",
            value=1.0
        )
        
        # Test getting recent logs (would need to implement this function)
        # For now, just test that the log exists
        recent_logs = crud.get_logs(db_session, rule_id=test_rule.id)
        assert len(recent_logs) >= 1

class TestAuditLogSecurity:
    """Test audit logging functionality"""
    
    def test_audit_log_creation(self, db_session, test_user):
        """Test creating audit log entries"""
        audit_log = AuditLog(
            user_id=test_user.id,
            action="TEST_ACTION",
            resource="test_resource",
            ip_address="127.0.0.1",
            success=True,
            details="Test audit log entry"
        )
        
        db_session.add(audit_log)
        db_session.commit()
        db_session.refresh(audit_log)
        
        assert audit_log.id is not None
        assert audit_log.user_id == test_user.id
        assert audit_log.action == "TEST_ACTION"
        assert audit_log.success == True
        assert audit_log.timestamp is not None

    def test_audit_log_queries(self, db_session, test_user):
        """Test querying audit logs"""
        # Create multiple audit log entries
        actions = ["LOGIN", "CREATE_RULE", "DELETE_RULE", "LOGOUT"]
        for action in actions:
            audit_log = AuditLog(
                user_id=test_user.id,
                action=action,
                ip_address="127.0.0.1",
                success=True,
                details=f"Test {action} action"
            )
            db_session.add(audit_log)
        
        db_session.commit()
        
        # Query all logs for user
        user_logs = db_session.query(AuditLog).filter(
            AuditLog.user_id == test_user.id
        ).all()
        assert len(user_logs) == 4
        
        # Query specific action
        login_logs = db_session.query(AuditLog).filter(
            AuditLog.user_id == test_user.id,
            AuditLog.action == "LOGIN"
        ).all()
        assert len(login_logs) == 1

class TestDatabaseSecurity:
    """Test database security features"""
    
    def test_foreign_key_constraints(self, db_session, test_user, test_rule):
        """Test foreign key constraints"""
        # Create log entry with valid foreign key
        log_entry = LogEntry(
            rule_id=test_rule.id,
            sensor_id="fk_test_sensor",
            metric="motion",
            value=1.0
        )
        db_session.add(log_entry)
        db_session.commit()
        
        # Verify relationship works
        assert log_entry.rule.id == test_rule.id
        assert test_rule.logs[0].event_id == log_entry.event_id

    def test_cascade_delete(self, db_session, test_rule):
        """Test cascade delete functionality"""
        # Create log entries for the rule
        for i in range(3):
            log_entry = LogEntry(
                rule_id=test_rule.id,
                sensor_id=f"cascade_sensor_{i}",
                metric="motion",
                value=float(i)
            )
            db_session.add(log_entry)
        db_session.commit()
        
        # Verify log entries exist
        log_count = db_session.query(LogEntry).filter(
            LogEntry.rule_id == test_rule.id
        ).count()
        assert log_count == 3
        
        # Delete the rule
        db_session.delete(test_rule)
        db_session.commit()
        
        # Verify log entries were cascade deleted
        remaining_logs = db_session.query(LogEntry).filter(
            LogEntry.rule_id == test_rule.id
        ).count()
        assert remaining_logs == 0

    def test_data_integrity(self, db_session):
        """Test data integrity constraints"""
        # Test unique username constraint
        user1 = User(
            username="unique_test",
            email="user1@test.com",
            hashed_password=get_password_hash("Pass123!"),
            role="viewer"
        )
        db_session.add(user1)
        db_session.commit()
        
        # Try to create another user with same username
        user2 = User(
            username="unique_test",  # Same username
            email="user2@test.com",
            hashed_password=get_password_hash("Pass123!"),
            role="viewer"
        )
        db_session.add(user2)
        
        # Should raise integrity error
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            db_session.commit()

class TestInputSanitization:
    """Test input sanitization functions"""
    
    def test_sanitize_input_function(self):
        """Test the sanitize_input function"""
        from src.security import sanitize_input
        
        # Test normal input
        clean_input = "normal_sensor_123"
        assert sanitize_input(clean_input) == clean_input
        
        # Test input with dangerous characters
        dangerous_input = "sensor<script>alert('xss')</script>"
        sanitized = sanitize_input(dangerous_input)
        assert "<script>" not in sanitized
        assert "alert" in sanitized  # Letters should remain
        
        # Test SQL injection patterns
        sql_injection = "sensor'; DROP TABLE rules; --"
        sanitized = sanitize_input(sql_injection)
        assert "'" not in sanitized
        assert ";" not in sanitized
        assert "--" not in sanitized

    def test_validate_sensor_id_function(self):
        """Test sensor ID validation"""
        from src.security import validate_sensor_id
        
        # Valid sensor IDs
        valid_ids = ["sensor_1", "bedroom-sensor", "LIVING_ROOM_01"]
        for sensor_id in valid_ids:
            assert validate_sensor_id(sensor_id) == True
        
        # Invalid sensor IDs
        invalid_ids = [
            "sensor with spaces",
            "sensor<script>",
            "sensor'injection",
            "a" * 51,  # Too long
            "",  # Empty
            "sensor/path"  # Invalid character
        ]
        for sensor_id in invalid_ids:
            assert validate_sensor_id(sensor_id) == False
