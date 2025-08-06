"""
models.py

Defines ORM models for rules, logs, and users using SQLAlchemy.
These models represent the database schema and are used for:
- Storing alert rules
- Logging triggered events
- User authentication and authorization
- Security auditing

Security & Best Practices:
- Uses declarative Base from database.py
- Uses proper data types and constraints
- Foreign key constraints are in place
- Includes __repr__ for clarity
- Password hashing for user authentication
- Role-based access control
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base


class User(Base):
    """
    User model for authentication and authorization.
    Supports role-based access control (RBAC).
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin, operator, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}', active={self.is_active})>"


class AuditLog(Base):
    """
    Audit log for tracking security events and user actions.
    Essential for compliance and security monitoring.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Null for system events
    action = Column(String(100), nullable=False)  # e.g., "CREATE_RULE", "LOGIN", "FAILED_LOGIN"
    resource = Column(String(100), nullable=True)  # e.g., "rule_123", "user_456"
    ip_address = Column(String(45), nullable=True)  # IPv4/IPv6
    user_agent = Column(String(255), nullable=True)
    success = Column(Boolean, default=True)
    details = Column(Text, nullable=True)  # JSON or text details
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Relationship
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', success={self.success})>"


class Rule(Base):
    """
    Rule model defines a rule for evaluating sensor data.
    A rule is triggered when: <value> <operator> <threshold>
    """
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    sensor_id = Column(String, nullable=False, index=True)  # e.g., "bedroom_sensor_1"
    metric = Column(String, nullable=False, index=True)     # e.g., "motion", "bed", "bathroom"
    operator = Column(String, nullable=False)               # e.g., ">", "<", "=="
    threshold = Column(Float, nullable=False)               # threshold to compare with
    target_topic = Column(String, nullable=False)           # e.g., "alerts/notify"
    payload = Column(String, nullable=False)                # e.g., "INACTIVITY_ALERT"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))  # auto timestamp

    # Relationship to log entries
    logs = relationship("LogEntry", back_populates="rule", cascade="all, delete")

    def __repr__(self):
        return (f"<Rule(id={self.id}, sensor_id='{self.sensor_id}', metric='{self.metric}', "
                f"operator='{self.operator}', threshold={self.threshold})>")


class LogEntry(Base):
    """
    LogEntry model records each time a rule was triggered.
    Useful for auditing and alert analytics.
    """
    __tablename__ = "log"

    event_id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("rules.id"), nullable=False)
    sensor_id = Column(String, nullable=False)
    metric = Column(String, nullable=False)
    value = Column(Float, nullable=False)
    triggered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to parent rule
    rule = relationship("Rule", back_populates="logs")

    def __repr__(self):
        return (f"<LogEntry(event_id={self.event_id}, rule_id={self.rule_id}, "
                f"sensor_id='{self.sensor_id}', metric='{self.metric}', value={self.value})>")