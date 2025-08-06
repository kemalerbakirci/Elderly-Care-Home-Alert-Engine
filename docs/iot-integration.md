# 🌐 IoT Integration Guide

Complete guide for integrating IoT sensors with the Elderly Care Home Alert Engine.

## 📡 MQTT Protocol Overview

The system uses MQTT (Message Queuing Telemetry Transport) for real-time IoT communication due to its:
- **Lightweight**: Minimal bandwidth usage
- **Reliable**: Quality of Service (QoS) levels
- **Scalable**: Supports thousands of sensors
- **Real-time**: Pub/Sub messaging pattern

## 🔧 MQTT Broker Setup

### Using Mosquitto (Recommended)

#### Installation

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install mosquitto mosquitto-clients
```

**macOS:**
```bash
brew install mosquitto
```

**Windows:**
Download from [Eclipse Mosquitto](https://mosquitto.org/download/)

#### Configuration

Create `/etc/mosquitto/mosquitto.conf`:
```conf
# Basic Configuration
port 1883
listener 1883
allow_anonymous true

# Security (Production)
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

# Logging
log_dest file /var/log/mosquitto/mosquitto.log
log_type error
log_type warning
log_type notice
log_type information

# Persistence
persistence true
persistence_location /var/lib/mosquitto/

# WebSocket Support (Optional)
listener 9001
protocol websockets
```

#### Start Mosquitto
```bash
# Development
mosquitto -v

# Production (with config)
mosquitto -c /etc/mosquitto/mosquitto.conf
```

### Alternative Brokers

#### Eclipse Mosquitto Cloud
- **HiveMQ Cloud**: Free tier available
- **AWS IoT Core**: Managed MQTT service
- **Azure IoT Hub**: Microsoft's IoT platform

## 📊 Topic Structure

### Sensor Data Topics
```
sensors/{sensor_id}/{metric}
```

**Examples:**
```
sensors/patient_001_heart_rate/bpm
sensors/bedroom_101_motion/motion
sensors/room_205_temperature/temperature
sensors/bathroom_102_humidity/humidity
sensors/emergency_button_003/pressed
```

### Alert Topics
```
alerts/{alert_type}
```

**Examples:**
```
alerts/medical_emergency
alerts/inactivity
alerts/environmental
alerts/system
```

## 🔌 Sensor Integration

### Message Format

Send **numeric values only** as message payload:

```bash
# Correct ✅
mosquitto_pub -h localhost -t "sensors/patient_001_heart_rate/bpm" -m "85.5"

# Incorrect ❌
mosquitto_pub -h localhost -t "sensors/patient_001_heart_rate/bpm" -m '{"value": 85.5}'
```

### Sensor Types and Metrics

#### Medical Sensors

**Heart Rate Monitor:**
```bash
# Topic: sensors/{patient_id}_heart_rate/bpm
mosquitto_pub -h localhost -t "sensors/patient_001_heart_rate/bpm" -m "72.0"
mosquitto_pub -h localhost -t "sensors/patient_002_heart_rate/bpm" -m "110.0"  # High
```

**Blood Pressure Monitor:**
```bash
# Systolic
mosquitto_pub -h localhost -t "sensors/patient_001_bp/systolic" -m "120.0"
# Diastolic  
mosquitto_pub -h localhost -t "sensors/patient_001_bp/diastolic" -m "80.0"
```

**Blood Oxygen (SpO2):**
```bash
mosquitto_pub -h localhost -t "sensors/patient_001_spo2/percentage" -m "98.0"
```

#### Activity Sensors

**Motion Detection:**
```bash
# Motion detected: 1.0, No motion: 0.0
mosquitto_pub -h localhost -t "sensors/bedroom_101_motion/motion" -m "1.0"
mosquitto_pub -h localhost -t "sensors/bathroom_102_motion/motion" -m "0.0"  # Alert
```

**Fall Detection:**
```bash
# Normal: 0.0, Fall detected: 1.0
mosquitto_pub -h localhost -t "sensors/patient_001_fall/detected" -m "1.0"  # Emergency
```

**Door Sensors:**
```bash
# Closed: 0.0, Open: 1.0
mosquitto_pub -h localhost -t "sensors/front_door/status" -m "1.0"
```

#### Environmental Sensors

**Temperature:**
```bash
# Celsius
mosquitto_pub -h localhost -t "sensors/room_205_temperature/celsius" -m "22.5"
mosquitto_pub -h localhost -t "sensors/room_205_temperature/celsius" -m "35.0"  # High

# Fahrenheit
mosquitto_pub -h localhost -t "sensors/room_205_temperature/fahrenheit" -m "72.5"
```

**Humidity:**
```bash
# Percentage
mosquitto_pub -h localhost -t "sensors/room_205_humidity/percentage" -m "45.0"
```

#### Emergency Sensors

**Panic Button:**
```bash
# Not pressed: 0.0, Pressed: 1.0
mosquitto_pub -h localhost -t "sensors/emergency_button_001/pressed" -m "1.0"  # Emergency
```

**Smoke Detector:**
```bash
# No smoke: 0.0, Smoke detected: 1.0
mosquitto_pub -h localhost -t "sensors/smoke_detector_kitchen/detected" -m "1.0"  # Emergency
```

## 🤖 Hardware Integration

### Arduino Example

```cpp
#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>

// WiFi credentials
const char* ssid = "YourWiFi";
const char* password = "YourPassword";

// MQTT Configuration
const char* mqtt_server = "192.168.1.100";
const int mqtt_port = 1883;

// Sensor Configuration
#define DHT_PIN 2
#define MOTION_PIN 4
#define DHT_TYPE DHT22

DHT dht(DHT_PIN, DHT_TYPE);
WiFiClient espClient;
PubSubClient client(espClient);

void setup() {
  Serial.begin(115200);
  
  // Initialize sensors
  dht.begin();
  pinMode(MOTION_PIN, INPUT);
  
  // Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  
  // Connect to MQTT
  client.setServer(mqtt_server, mqtt_port);
  reconnect();
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();
  
  // Read sensors every 30 seconds
  static unsigned long lastRead = 0;
  if (millis() - lastRead > 30000) {
    publishSensorData();
    lastRead = millis();
  }
}

void publishSensorData() {
  // Temperature
  float temp = dht.readTemperature();
  if (!isnan(temp)) {
    String tempTopic = "sensors/room_101_temperature/celsius";
    client.publish(tempTopic.c_str(), String(temp).c_str());
  }
  
  // Humidity
  float humidity = dht.readHumidity();
  if (!isnan(humidity)) {
    String humidityTopic = "sensors/room_101_humidity/percentage";
    client.publish(humidityTopic.c_str(), String(humidity).c_str());
  }
  
  // Motion
  int motion = digitalRead(MOTION_PIN);
  String motionTopic = "sensors/room_101_motion/motion";
  client.publish(motionTopic.c_str(), String(motion).c_str());
}

void reconnect() {
  while (!client.connected()) {
    String clientId = "ElderlyCare-" + String(random(0xffff), HEX);
    if (client.connect(clientId.c_str())) {
      Serial.println("MQTT Connected");
    } else {
      delay(5000);
    }
  }
}
```

### Raspberry Pi Example

```python
#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import time
import random
import json
from datetime import datetime

# MQTT Configuration
MQTT_HOST = "localhost"
MQTT_PORT = 1883
DEVICE_ID = "raspberry_pi_001"

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"Connected to MQTT broker")
    else:
        print(f"Failed to connect, return code {rc}")

def simulate_heart_rate():
    """Simulate heart rate sensor"""
    # Normal: 60-100, Alert: >100
    return random.uniform(60, 120)

def simulate_motion():
    """Simulate motion sensor"""
    # 90% chance of motion during day
    return random.choice([0.0, 1.0])

def simulate_temperature():
    """Simulate room temperature"""
    # Normal: 20-25°C, Alert: >30°C or <15°C
    return random.uniform(18, 32)

def main():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    
    try:
        client.connect(MQTT_HOST, MQTT_PORT, 60)
        client.loop_start()
        
        print(f"Starting sensor simulation...")
        
        while True:
            # Heart rate sensor
            heart_rate = simulate_heart_rate()
            client.publish("sensors/patient_001_heart_rate/bpm", str(heart_rate))
            print(f"Heart Rate: {heart_rate:.1f} bpm")
            
            # Motion sensor
            motion = simulate_motion()
            client.publish("sensors/bedroom_101_motion/motion", str(motion))
            print(f"Motion: {'Detected' if motion else 'None'}")
            
            # Temperature sensor
            temperature = simulate_temperature()
            client.publish("sensors/room_101_temperature/celsius", str(temperature))
            print(f"Temperature: {temperature:.1f}°C")
            
            print("-" * 30)
            time.sleep(10)  # Send data every 10 seconds
            
    except KeyboardInterrupt:
        print("Simulation stopped")
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
```

## 📱 Mobile Integration

### React Native Example

```javascript
import { Client } from 'react-native-paho-mqtt';

class IoTSensorManager {
  constructor() {
    this.client = new Client({
      uri: 'ws://your-mqtt-broker:9001',
      clientId: 'mobile-app-' + Math.random().toString(16).substr(2, 8)
    });
    
    this.client.on('connectionLost', this.onConnectionLost);
    this.client.on('messageArrived', this.onMessageArrived);
  }
  
  connect() {
    this.client.connect({
      onSuccess: this.onConnect,
      onFailure: this.onFailure
    });
  }
  
  onConnect = () => {
    console.log('Connected to MQTT broker');
    // Subscribe to alerts
    this.client.subscribe('alerts/#');
  }
  
  onMessageArrived = (message) => {
    const topic = message.destinationName;
    const payload = message.payloadString;
    
    if (topic.startsWith('alerts/')) {
      this.handleAlert(topic, payload);
    }
  }
  
  handleAlert(topic, payload) {
    // Show push notification
    const alertType = topic.split('/')[1];
    this.showNotification(`${alertType}: ${payload}`);
  }
  
  publishSensorData(sensorId, metric, value) {
    const topic = `sensors/${sensorId}/${metric}`;
    this.client.send(topic, value.toString());
  }
}
```

## 🔒 Security Best Practices

### MQTT Security

#### Authentication
```bash
# Create password file
sudo mosquitto_passwd -c /etc/mosquitto/passwd admin
sudo mosquitto_passwd /etc/mosquitto/passwd sensor_user
```

#### TLS/SSL Configuration
```conf
# /etc/mosquitto/mosquitto.conf
port 8883
cafile /etc/mosquitto/ca_certificates/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
tls_version tlsv1.2
```

#### Access Control Lists (ACL)
```conf
# /etc/mosquitto/acl
# Admin full access
user admin
topic readwrite #

# Sensors can only publish to their topics
user sensor_001
topic write sensors/sensor_001/+

# Dashboard can only read
user dashboard
topic read sensors/+/+
topic read alerts/+
```

### Sensor Security

1. **Device Authentication**: Unique certificates per device
2. **Data Encryption**: TLS for all communications
3. **Regular Updates**: Keep firmware updated
4. **Network Segmentation**: Separate IoT VLAN
5. **Monitoring**: Log all MQTT connections

## 🧪 Testing IoT Integration

### Manual Testing

```bash
# Test sensor data
mosquitto_pub -h localhost -t "sensors/test_heart_rate/bpm" -m "120.0"

# Monitor alerts
mosquitto_sub -h localhost -t "alerts/#" -v

# Test environmental sensor
mosquitto_pub -h localhost -t "sensors/test_temperature/celsius" -m "35.0"
```

### Automated Testing Script

```python
# test_iot_integration.py
import paho.mqtt.client as mqtt
import time
import json

def test_sensor_integration():
    """Test complete sensor to alert workflow"""
    
    alerts_received = []
    
    def on_alert(client, userdata, message):
        alerts_received.append({
            'topic': message.topic,
            'payload': message.payload.decode(),
            'timestamp': time.time()
        })
    
    # Subscribe to alerts
    alert_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    alert_client.on_message = on_alert
    alert_client.connect("localhost", 1883, 60)
    alert_client.subscribe("alerts/#")
    alert_client.loop_start()
    
    # Publish test sensor data
    sensor_client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    sensor_client.connect("localhost", 1883, 60)
    
    test_cases = [
        ("sensors/patient_001_heart_rate/bpm", "120.0", "medical_emergency"),
        ("sensors/bedroom_101_motion/motion", "0.0", "inactivity"),
        ("sensors/room_205_temperature/celsius", "35.0", "environmental")
    ]
    
    for topic, value, expected_alert in test_cases:
        print(f"Testing: {topic} = {value}")
        sensor_client.publish(topic, value)
        time.sleep(2)  # Wait for processing
        
        # Check if alert was received
        matching_alerts = [a for a in alerts_received if expected_alert in a['topic']]
        if matching_alerts:
            print(f"✅ Alert received: {matching_alerts[-1]['topic']}")
        else:
            print(f"❌ No alert received for {expected_alert}")
    
    alert_client.loop_stop()
    sensor_client.disconnect()
    alert_client.disconnect()

if __name__ == "__main__":
    test_sensor_integration()
```

## 📊 Monitoring and Debugging

### MQTT Debug Commands

```bash
# Monitor all sensor data
mosquitto_sub -h localhost -t "sensors/#" -v

# Monitor all alerts
mosquitto_sub -h localhost -t "alerts/#" -v

# Check broker status
mosquitto_sub -h localhost -t '$SYS/#'

# Test connectivity
mosquitto_pub -h localhost -t "test/connection" -m "ping"
```

### Troubleshooting

#### Common Issues

1. **Connection Refused**
   ```bash
   # Check if broker is running
   sudo systemctl status mosquitto
   
   # Check port availability
   netstat -an | grep 1883
   ```

2. **Messages Not Received**
   ```bash
   # Check topic subscription
   mosquitto_sub -h localhost -t "sensors/#" -v
   
   # Verify message format
   mosquitto_pub -h localhost -t "test/debug" -m "test_message"
   ```

3. **Authentication Failed**
   ```bash
   # Test with credentials
   mosquitto_pub -h localhost -u username -P password -t "test" -m "auth_test"
   ```

### Performance Monitoring

```python
# mqtt_monitor.py
import paho.mqtt.client as mqtt
import time
from collections import defaultdict

class MQTTMonitor:
    def __init__(self):
        self.message_count = defaultdict(int)
        self.start_time = time.time()
    
    def on_message(self, client, userdata, message):
        topic = message.topic
        self.message_count[topic] += 1
        
        # Log high-frequency topics
        if self.message_count[topic] % 100 == 0:
            print(f"Topic {topic}: {self.message_count[topic]} messages")
    
    def print_stats(self):
        elapsed = time.time() - self.start_time
        total_messages = sum(self.message_count.values())
        
        print(f"\n📊 MQTT Statistics ({elapsed:.1f}s)")
        print(f"Total messages: {total_messages}")
        print(f"Messages/second: {total_messages/elapsed:.2f}")
        print(f"Active topics: {len(self.message_count)}")
```

This comprehensive IoT integration guide provides everything needed to connect sensors and devices to the Elderly Care Home Alert Engine!
