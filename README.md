# 🏥 Elderly Care Home Alert Engine

A comprehensive IoT monitoring system designed specifically for elderly care facilities, providing real-time health monitoring, activity tracking, and emergency alert capabilities.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)
![MQTT](https://img.shields.io/badge/MQTT-660066?style=flat&logo=mqtt)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=flat&logo=sqlite)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🌟 Features

### 🚨 Real-time Alert System
- **Medical Emergency Detection**: Heart rate, blood pressure, and vital sign monitoring
- **Activity Monitoring**: Motion detection, fall detection, and inactivity alerts
- **Environmental Monitoring**: Temperature, humidity, and air quality alerts
- **Customizable Thresholds**: Configurable alert rules per patient/room

### 🔐 Security & Authentication
- **JWT-based Authentication**: Secure API access with role-based permissions
- **Audit Logging**: Complete activity tracking for compliance
- **Input Validation**: SQL injection protection and data sanitization
- **Security Headers**: CORS protection and security middleware

### 📡 IoT Integration
- **MQTT Protocol**: Real-time sensor data ingestion
- **Multi-sensor Support**: Temperature, motion, heart rate, and custom sensors
- **Scalable Architecture**: Support for hundreds of sensors
- **Real-time Processing**: Sub-second alert response times

### 📊 Data Management
- **SQLite Database**: Reliable data storage with ACID compliance
- **RESTful API**: Complete CRUD operations for rules and logs
- **Historical Data**: Comprehensive logging and reporting capabilities
- **Data Export**: API endpoints for data analysis and reporting

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MQTT Broker (Mosquitto recommended)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/kemalerbakirci/Elderly-Care-Home-Alert-Engine.git
cd Elderly-Care-Home-Alert-Engine

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "from src.database import create_tables; create_tables()"

# Start MQTT broker (separate terminal)
mosquitto -v

# Run the application
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

### First Test

```bash
# Health check
curl http://localhost:8000/health

# Create a test alert rule
curl -X POST http://localhost:8000/rules \
  -H "Content-Type: application/json" \
  -d '{
    "sensor_id": "patient_001_heart_rate",
    "metric": "bpm",
    "operator": ">",
    "threshold": 100.0,
    "alert_topic": "alerts/medical_emergency"
  }'

# Simulate sensor data
mosquitto_pub -h localhost -t "sensors/patient_001_heart_rate/bpm" -m "120.0"
```

## 📖 Documentation

- **[API Documentation](docs/api.md)** - Complete REST API reference
- **[IoT Integration Guide](docs/iot-integration.md)** - MQTT setup and sensor configuration
- **[Deployment Guide](docs/deployment.md)** - Production deployment instructions
- **[Security Guide](docs/security.md)** - Security features and best practices
- **[Testing Guide](docs/testing.md)** - Comprehensive testing strategies
- **[Configuration Guide](docs/configuration.md)** - Environment and system configuration

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   IoT Sensors   │───▶│   MQTT Broker    │───▶│  Alert Engine   │
│                 │    │                  │    │                 │
│ • Heart Rate    │    │  • Mosquitto     │    │ • Rule Engine   │
│ • Motion        │    │  • Topic-based   │    │ • Real-time     │
│ • Temperature   │    │  • Pub/Sub       │    │ • Processing    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐             │
│   Web Dashboard │◀───│   FastAPI App    │◀────────────┘
│                 │    │                  │
│ • Real-time     │    │ • REST API       │
│ • Monitoring    │    │ • Authentication │
│ • Alerts        │    │ • Database       │
└─────────────────┘    └──────────────────┘
```

## 🔧 Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=sqlite:///./elderly_care.db

# MQTT Configuration
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_USERNAME=
MQTT_PASSWORD=

# Security
SECRET_KEY=your-super-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false
```

### MQTT Topic Structure

```
sensors/{sensor_id}/{metric}
├── patient_001_heart_rate/bpm
├── bedroom_101_motion/motion
├── room_205_temperature/temperature
└── bathroom_102_humidity/humidity

alerts/{alert_type}
├── medical_emergency
├── inactivity
├── environmental
└── system
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src

# Run integration tests
python -m pytest tests/integration/

# Live system demo
python test_alerts.py
```

## 📊 Monitoring & Alerts

### Alert Types
- 🚨 **Medical Emergency**: Critical vital signs
- 🚪 **Inactivity Alert**: No movement detected
- 🌡️ **Environmental**: Temperature/humidity out of range
- 🔋 **System Alert**: Sensor battery low or offline

### Real-time Dashboard
Access the monitoring dashboard at `http://localhost:8000/dashboard` (coming soon)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **FastAPI**: For the excellent web framework
- **Paho MQTT**: For reliable MQTT client implementation
- **SQLAlchemy**: For robust database operations
- **Elderly Care Community**: For inspiration and requirements

## 📞 Support

- 📧 Email: support@elderlycare-engine.com
- 🐛 Issues: [GitHub Issues](https://github.com/kemalerbakirci/Elderly-Care-Home-Alert-Engine/issues)
- 📖 Wiki: [Project Wiki](https://github.com/kemalerbakirci/Elderly-Care-Home-Alert-Engine/wiki)

---

**Built with ❤️ for elderly care facilities worldwide**
