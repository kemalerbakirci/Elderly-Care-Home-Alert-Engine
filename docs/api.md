# 🔌 API Documentation

Complete reference for the Elderly Care Home Alert Engine REST API.

## Base URL
```
http://localhost:8000
```

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```http
Authorization: Bearer <your-jwt-token>
```

### Obtain Token

**POST** `/auth/login`

Request:
```json
{
  "username": "admin",
  "password": "your-password"
}
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

## Endpoints

### 🏠 Health Check

**GET** `/health`

Check system health and status.

Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-08-06T12:00:00Z",
  "version": "1.0.0",
  "services": {
    "api": "online",
    "mqtt": "online",
    "database": "online"
  }
}
```

### 📏 Alert Rules

#### Get All Rules

**GET** `/rules`

Retrieve all alert rules.

Response:
```json
[
  {
    "id": 1,
    "sensor_id": "patient_001_heart_rate",
    "metric": "bpm",
    "operator": ">",
    "threshold": 100.0,
    "alert_topic": "alerts/medical_emergency",
    "name": "High Heart Rate Alert",
    "description": "Alert when heart rate exceeds 100 bpm",
    "enabled": true,
    "created_at": "2025-08-06T10:00:00Z",
    "updated_at": "2025-08-06T10:00:00Z"
  }
]
```

#### Create Rule

**POST** `/rules`

Create a new alert rule.

Request:
```json
{
  "sensor_id": "patient_001_heart_rate",
  "metric": "bpm",
  "operator": ">",
  "threshold": 100.0,
  "alert_topic": "alerts/medical_emergency",
  "name": "High Heart Rate Alert",
  "description": "Alert when heart rate exceeds 100 bpm"
}
```

**Operators:** `>`, `<`, `>=`, `<=`, `==`, `!=`

#### Update Rule

**PUT** `/rules/{rule_id}`

Update an existing rule.

Request: Same as create rule

#### Delete Rule

**DELETE** `/rules/{rule_id}`

Delete a rule by ID.

Response: `204 No Content`

### 📊 Logs and History

#### Get Alert Logs

**GET** `/logs`

Retrieve alert logs with optional filtering.

Query Parameters:
- `sensor_id` (optional): Filter by sensor ID
- `rule_id` (optional): Filter by rule ID
- `start_date` (optional): Filter from date (ISO format)
- `end_date` (optional): Filter to date (ISO format)
- `limit` (optional): Limit results (default: 100)

Response:
```json
[
  {
    "id": 1,
    "rule_id": 1,
    "sensor_id": "patient_001_heart_rate",
    "metric": "bpm",
    "value": 120.5,
    "threshold": 100.0,
    "operator": ">",
    "alert_sent": true,
    "alert_topic": "alerts/medical_emergency",
    "timestamp": "2025-08-06T12:30:00Z"
  }
]
```

### 👥 User Management

#### Get Users

**GET** `/auth/users`

Retrieve all users (admin only).

Response:
```json
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "is_active": true,
    "created_at": "2025-08-06T10:00:00Z"
  }
]
```

#### Create User

**POST** `/auth/users`

Create a new user (admin only).

Request:
```json
{
  "username": "nurse_john",
  "email": "john@facility.com",
  "password": "secure_password",
  "role": "nurse"
}
```

**Roles:** `admin`, `nurse`, `doctor`, `viewer`

### 📈 Analytics

#### Get Dashboard Data

**GET** `/dashboard/stats`

Get real-time statistics for dashboard.

Response:
```json
{
  "total_sensors": 25,
  "active_rules": 15,
  "alerts_today": 8,
  "alerts_this_week": 42,
  "system_health": "healthy",
  "recent_alerts": [
    {
      "sensor_id": "patient_001_heart_rate",
      "alert_type": "medical_emergency",
      "timestamp": "2025-08-06T12:45:00Z"
    }
  ]
}
```

#### Get Sensor Status

**GET** `/sensors/status`

Get status of all sensors.

Response:
```json
[
  {
    "sensor_id": "patient_001_heart_rate",
    "last_seen": "2025-08-06T12:45:00Z",
    "status": "online",
    "last_value": 85.0,
    "battery_level": 95
  }
]
```

## Error Responses

### Standard Error Format

```json
{
  "detail": "Error description",
  "error_code": "VALIDATION_ERROR",
  "timestamp": "2025-08-06T12:00:00Z"
}
```

### HTTP Status Codes

- `200` - Success
- `201` - Created
- `204` - No Content
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Validation Error
- `500` - Internal Server Error

## Rate Limiting

- **API Calls**: 1000 requests per hour per IP
- **Authentication**: 10 login attempts per minute per IP

## Webhooks

### Alert Webhooks

Configure webhooks to receive real-time alerts.

**POST** `/webhooks/alerts`

Request:
```json
{
  "url": "https://your-system.com/webhook",
  "events": ["medical_emergency", "inactivity"],
  "secret": "webhook_secret_key"
}
```

### Webhook Payload

```json
{
  "event": "medical_emergency",
  "sensor_id": "patient_001_heart_rate",
  "value": 125.0,
  "threshold": 100.0,
  "timestamp": "2025-08-06T12:30:00Z",
  "rule_id": 1,
  "alert_topic": "alerts/medical_emergency"
}
```

## SDK Examples

### Python

```python
import requests

# Authenticate
response = requests.post('http://localhost:8000/auth/login', json={
    'username': 'admin',
    'password': 'password'
})
token = response.json()['access_token']

# Create headers
headers = {'Authorization': f'Bearer {token}'}

# Create alert rule
rule_data = {
    'sensor_id': 'patient_001_heart_rate',
    'metric': 'bpm',
    'operator': '>',
    'threshold': 100.0,
    'alert_topic': 'alerts/medical_emergency'
}
response = requests.post('http://localhost:8000/rules', 
                        json=rule_data, headers=headers)
```

### JavaScript

```javascript
// Authenticate
const authResponse = await fetch('http://localhost:8000/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        username: 'admin',
        password: 'password'
    })
});
const { access_token } = await authResponse.json();

// Get all rules
const rulesResponse = await fetch('http://localhost:8000/rules', {
    headers: { 'Authorization': `Bearer ${access_token}` }
});
const rules = await rulesResponse.json();
```

### cURL

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' | \
  jq -r '.access_token')

# Create rule
curl -X POST http://localhost:8000/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sensor_id": "patient_001_heart_rate",
    "metric": "bpm", 
    "operator": ">",
    "threshold": 100.0,
    "alert_topic": "alerts/medical_emergency"
  }'
```

## Testing

### Postman Collection

Import the [Postman collection](../tests/api/elderly-care-api.postman_collection.json) for easy API testing.

### OpenAPI Documentation

Interactive API documentation available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
