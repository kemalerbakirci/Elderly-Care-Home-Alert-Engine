"""
test_api.py

Tests the REST API for managing rules.
"""

import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.database import engine
from src.models import Base

# Create all tables before running tests
Base.metadata.create_all(bind=engine)

client = TestClient(app)

def test_create_rule():
    payload = {
        "sensor_id": "bed_001",
        "metric": "motion",
        "operator": "==",
        "threshold": 0.0,
        "target_topic": "alerts/nurse",
        "payload": "MOTION_OFF"
    }
    response = client.post("/rules", json=payload)
    assert response.status_code == 201
    assert "id" in response.json()
    assert response.json()["sensor_id"] == "bed_001"

def test_list_rules():
    response = client.get("/rules")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_delete_rule():
    # First create rule
    payload = {
        "sensor_id": "temp_001",
        "metric": "temperature",
        "operator": ">",
        "threshold": 38.0,
        "target_topic": "alerts/caregiver",
        "payload": "FEVER_ALERT"
    }
    create_resp = client.post("/rules", json=payload)
    rule_id = create_resp.json()["id"]

    # Now delete it
    delete_resp = client.delete(f"/rules/{rule_id}")
    assert delete_resp.status_code == 204