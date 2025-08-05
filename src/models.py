"""
models.py

Defines ORM models for rules and logs using SQLAlchemy.
These models represent the database schema and are used for:
- Storing alert rules
- Logging triggered events

Security & Best Practices:
- Uses declarative Base from database.py
- Uses proper data types and constraints
- Foreign key constraints are in place
- Includes __repr__ for clarity
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base


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
    created_at = Column(DateTime, default=datetime.utcnow)  # auto timestamp

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
    triggered_at = Column(DateTime, default=datetime.utcnow)

    # Relationship to parent rule
    rule = relationship("Rule", back_populates="logs")

    def __repr__(self):
        return (f"<LogEntry(event_id={self.event_id}, rule_id={self.rule_id}, "
                f"sensor_id='{self.sensor_id}', metric='{self.metric}', value={self.value})>")