"""
test_api.py

Tests the REST API for managing rules.
"""

import pytest

def test_create_rule(client):
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

def test_list_rules(client):
    response = client.get("/rules")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_delete_rule(client):
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
    assert create_resp.status_code == 201
    rule_id = create_resp.json()["id"]
    
    # Then delete it
    delete_resp = client.delete(f"/rules/{rule_id}")
    assert delete_resp.status_code == 204  # No Content is correct for successful delete
    
    # Verify deletion by listing rules
    list_resp = client.get("/rules")
    assert list_resp.status_code == 200
    rules = list_resp.json()
    rule_ids = [rule["id"] for rule in rules]
    assert rule_id not in rule_ids