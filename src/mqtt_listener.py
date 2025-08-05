"""
mqtt_listener.py

Listens to MQTT sensor data and applies rule evaluation in real time.
Triggers actions and logs events.
"""

import os
import json
import threading
from dotenv import load_dotenv
import paho.mqtt.client as mqtt
from sqlalchemy.orm import Session
from datetime import datetime

from . import database, crud, models

# Load env variables
load_dotenv()
BROKER_HOST = os.getenv("BROKER_HOST", "localhost")
BROKER_PORT = int(os.getenv("BROKER_PORT", "1883"))

# MQTT Client
client = mqtt.Client(client_id="elderly-care-alert-engine")


def evaluate_and_act(sensor_id: str, metric: str, value: float, db: Session):
    """
    Check matching rules and trigger actions if any rule is satisfied.
    """
    rules = crud.get_matching_rules(db, sensor_id, metric)
    for rule in rules:
        triggered = False
        if rule.operator == ">" and value > rule.threshold:
            triggered = True
        elif rule.operator == "<" and value < rule.threshold:
            triggered = True
        elif rule.operator == "==" and value == rule.threshold:
            triggered = True
        elif rule.operator == ">=" and value >= rule.threshold:
            triggered = True
        elif rule.operator == "<=" and value <= rule.threshold:
            triggered = True
        elif rule.operator == "!=" and value != rule.threshold:
            triggered = True

        if triggered:
            print(f"🚨 Rule triggered: {rule.id} - Publishing to {rule.target_topic}")
            client.publish(rule.target_topic, rule.payload)
            crud.log_event(
                db,
                rule_id=rule.id,
                sensor_id=sensor_id,
                metric=metric,
                value=value
                
            )


# MQTT Callback
def on_message(client, userdata, msg):
    """
    Callback when message arrives on any subscribed topic.
    """
    topic = msg.topic  # Example: sensors/bed1/motion
    payload = msg.payload.decode()

    try:
        sensor_id, metric = topic.split("/")[1:]  # Extract from topic
        value = float(payload)  # Expect plain numeric payload
    except Exception as e:
        print(f"⚠️ Invalid message format: {topic} -> {payload} ({e})")
        return

    # Create DB session
    db = database.SessionLocal()
    try:
        evaluate_and_act(sensor_id, metric, value, db)
    finally:
        db.close()


def run_mqtt_loop():
    """
    Connect and listen to MQTT broker indefinitely.
    """
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT)
    client.subscribe("sensors/#")
    print(f"✅ MQTT connected to {BROKER_HOST}:{BROKER_PORT} | Subscribed to sensors/#")
    client.loop_forever()


def start_mqtt_thread():
    """
    Starts the MQTT listener in a background thread.
    """
    thread = threading.Thread(target=run_mqtt_loop, daemon=True)
    thread.start()