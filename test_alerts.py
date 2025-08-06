#!/usr/bin/env python3
"""
Real-time IoT Alert Monitoring Demo
This script demonstrates the Elderly Care Alert Engine in action
"""

import paho.mqtt.client as mqtt
import time
import threading
import json
from datetime import datetime

# MQTT Configuration
MQTT_HOST = "localhost"
MQTT_PORT = 1883
SENSOR_TOPIC = "sensors"
ALERT_TOPIC = "alerts"

# Alert storage
alerts_received = []

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("🔗 Connected to MQTT broker")
        client.subscribe(f"{ALERT_TOPIC}/#")
        print(f"📡 Subscribed to {ALERT_TOPIC}/#")
    else:
        print(f"❌ Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode()
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        alert_data = {
            "timestamp": timestamp,
            "topic": topic,
            "message": payload
        }
        alerts_received.append(alert_data)
        
        print(f"\n🚨 ALERT RECEIVED at {timestamp}")
        print(f"   Topic: {topic}")
        print(f"   Message: {payload}")
        print("   " + "="*50)
        
    except Exception as e:
        print(f"❌ Error processing alert: {e}")

def publish_sensor_data(client):
    """Publish test sensor data that should trigger alerts"""
    
    test_scenarios = [
        {
            "name": "💓 High Heart Rate Emergency",
            "topic": "sensors/patient_001_heart_rate/bpm",
            "value": "125.0",
            "description": "Heart rate 125 bpm (> 100 threshold)"
        },
        {
            "name": "🚪 Bedroom Inactivity",
            "topic": "sensors/bedroom_101_motion/motion", 
            "value": "0.0",
            "description": "No motion detected (== 0.0 threshold)"
        },
        {
            "name": "💓 Critical Heart Rate",
            "topic": "sensors/patient_001_heart_rate/bpm",
            "value": "140.0", 
            "description": "Heart rate 140 bpm (> 100 threshold)"
        }
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n📊 Test {i}/3: {scenario['name']}")
        print(f"   Publishing: {scenario['description']}")
        print(f"   Topic: {scenario['topic']}")
        print(f"   Value: {scenario['value']}")
        
        client.publish(scenario['topic'], scenario['value'])
        print("   ✅ Published! Waiting for alert...")
        time.sleep(3)  # Wait for alert processing

def main():
    print("🏥 Elderly Care Alert Engine - Real-time Demo")
    print("=" * 60)
    print("This demo will:")
    print("1. Connect to MQTT broker")
    print("2. Subscribe to alert topics")  
    print("3. Publish sensor data that triggers alerts")
    print("4. Display received alerts in real-time")
    print("=" * 60)
    
    # Create MQTT client
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        # Connect to broker
        client.connect(MQTT_HOST, MQTT_PORT, 60)
        
        # Start network loop in background
        client.loop_start()
        time.sleep(2)  # Wait for connection
        
        # Publish test sensor data
        publish_sensor_data(client)
        
        # Wait a bit more for any delayed alerts
        print("\n⏳ Waiting for final alerts...")
        time.sleep(5)
        
        # Summary
        print(f"\n📈 DEMO SUMMARY")
        print("=" * 40)
        print(f"Total alerts received: {len(alerts_received)}")
        
        if alerts_received:
            print("\n🚨 Alert Log:")
            for alert in alerts_received:
                print(f"   [{alert['timestamp']}] {alert['topic']}: {alert['message']}")
        else:
            print("⚠️  No alerts captured (check MQTT broker and rules)")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
