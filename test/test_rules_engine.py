"""
test_rules_engine.py

Tests rule evaluation logic by simulating MQTT input.
"""

import pytest
from src.crud import create_rule, log_event, get_logs
from src.database import SessionLocal, engine
from src.schemas import RuleCreate
from src.models import LogEntry, Base

# Create all tables before running tests
Base.metadata.create_all(bind=engine)

@pytest.fixture
def db():
    db = SessionLocal()
    yield db
    db.close()

def test_rule_trigger_and_log(db):
    # Insert test rule
    test_rule = RuleCreate(
        sensor_id="bed_101",
        metric="motion",
        operator="==",
        threshold=0.0,
        target_topic="alerts/emergency",
        payload="NO_MOTION_ALERT"
    )
    rule = create_rule(db, test_rule)

    # Simulate sensor input matching the rule
    from src.mqtt_listener import evaluate_and_act
    from src.database import SessionLocal
    
    test_db = SessionLocal()
    try:
        # Call the evaluation function directly with test data
        evaluate_and_act("bed_101", "motion", 0.0, test_db)
    finally:
        test_db.close()

    # Check logs
    logs = get_logs(db, rule_id=rule.id)
    assert len(logs) >= 1
    # Verify that the rule was triggered and logged
    last_log = logs[-1]
    assert last_log.rule_id == rule.id
    assert last_log.sensor_id == "bed_101"
    assert last_log.metric == "motion"
    assert last_log.value == 0.0