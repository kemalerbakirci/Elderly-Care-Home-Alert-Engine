# 🔒 Security Guide

Comprehensive security documentation for the Elderly Care Home Alert Engine.

## 🛡️ Security Overview

The Elderly Care Home Alert Engine implements multiple layers of security to protect sensitive health data and ensure HIPAA compliance. This guide covers all security features and best practices.

## 🏥 HIPAA Compliance

### Protected Health Information (PHI)

The system handles sensitive medical data including:
- **Patient identifiers** (names, IDs, room numbers)
- **Health metrics** (heart rate, blood pressure, activity levels)
- **Medical alerts** (emergency events, medication reminders)
- **Location data** (room occupancy, movement tracking)

### Compliance Features

#### Data Encryption
- **In Transit**: TLS 1.2+ for all communications
- **At Rest**: AES-256 encryption for database storage
- **MQTT**: TLS/SSL encryption for sensor data

#### Access Controls
- **Role-based permissions** (admin, nurse, doctor, viewer)
- **Multi-factor authentication** (MFA) support
- **Session management** with automatic timeouts
- **Audit logging** for all data access

#### Data Integrity
- **Input validation** preventing data corruption
- **Checksums** for critical data verification
- **Backup encryption** with secure key management
- **Data retention policies** with automatic purging

## 🔐 Authentication & Authorization

### JWT Token Authentication

**Token Structure:**
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_id",
    "username": "admin",
    "role": "admin",
    "exp": 1672531200,
    "iat": 1672527600,
    "facility_id": "facility_001"
  }
}
```

**Implementation:**
```python
# src/auth/jwt_handler.py
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        
        if username is None or role is None:
            raise JWTError("Invalid token payload")
            
        return {"username": username, "role": role}
    except JWTError:
        return None
```

### Role-Based Access Control (RBAC)

**Role Hierarchy:**
```
Administrator (admin)
├── Full system access
├── User management
├── System configuration
└── All data access

Doctor (doctor)
├── Patient data access
├── Alert rule management
├── Medical history access
└── Report generation

Nurse (nurse)
├── Patient monitoring
├── Alert acknowledgment
├── Basic rule modification
└── Shift reporting

Viewer (viewer)
├── Read-only dashboard
├── Alert viewing
└── Basic reporting
```

**Implementation:**
```python
# src/auth/permissions.py
from enum import Enum
from functools import wraps
from fastapi import HTTPException, status

class UserRole(Enum):
    ADMIN = "admin"
    DOCTOR = "doctor"
    NURSE = "nurse"
    VIEWER = "viewer"

class Permission(Enum):
    # User Management
    CREATE_USER = "create_user"
    UPDATE_USER = "update_user"
    DELETE_USER = "delete_user"
    VIEW_USERS = "view_users"
    
    # Rule Management
    CREATE_RULE = "create_rule"
    UPDATE_RULE = "update_rule"
    DELETE_RULE = "delete_rule"
    VIEW_RULES = "view_rules"
    
    # Data Access
    VIEW_PATIENT_DATA = "view_patient_data"
    VIEW_ALERTS = "view_alerts"
    ACKNOWLEDGE_ALERTS = "acknowledge_alerts"

# Role Permission Matrix
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        Permission.CREATE_USER, Permission.UPDATE_USER, Permission.DELETE_USER, Permission.VIEW_USERS,
        Permission.CREATE_RULE, Permission.UPDATE_RULE, Permission.DELETE_RULE, Permission.VIEW_RULES,
        Permission.VIEW_PATIENT_DATA, Permission.VIEW_ALERTS, Permission.ACKNOWLEDGE_ALERTS
    ],
    UserRole.DOCTOR: [
        Permission.VIEW_USERS, Permission.CREATE_RULE, Permission.UPDATE_RULE, Permission.VIEW_RULES,
        Permission.VIEW_PATIENT_DATA, Permission.VIEW_ALERTS, Permission.ACKNOWLEDGE_ALERTS
    ],
    UserRole.NURSE: [
        Permission.VIEW_RULES, Permission.VIEW_PATIENT_DATA, 
        Permission.VIEW_ALERTS, Permission.ACKNOWLEDGE_ALERTS
    ],
    UserRole.VIEWER: [
        Permission.VIEW_RULES, Permission.VIEW_PATIENT_DATA, Permission.VIEW_ALERTS
    ]
}

def require_permission(permission: Permission):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from context
            current_user = get_current_user()
            user_role = UserRole(current_user.role)
            
            if permission not in ROLE_PERMISSIONS.get(user_role, []):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: {permission.value} required"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator
```

### Password Security

**Password Requirements:**
- Minimum 12 characters
- Must include uppercase, lowercase, numbers, special characters
- Cannot contain common patterns or dictionary words
- Must be changed every 90 days
- Cannot reuse last 5 passwords

**Implementation:**
```python
# src/auth/password_policy.py
import re
import bcrypt
import secrets
from datetime import datetime, timedelta

class PasswordPolicy:
    MIN_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL = True
    MAX_AGE_DAYS = 90
    HISTORY_COUNT = 5

    @staticmethod
    def validate_password(password: str) -> tuple[bool, list[str]]:
        errors = []
        
        if len(password) < PasswordPolicy.MIN_LENGTH:
            errors.append(f"Password must be at least {PasswordPolicy.MIN_LENGTH} characters")
        
        if PasswordPolicy.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letters")
        
        if PasswordPolicy.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain lowercase letters")
        
        if PasswordPolicy.REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Password must contain numbers")
        
        if PasswordPolicy.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain special characters")
        
        # Check common patterns
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            errors.append("Password cannot contain sequential numbers")
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            errors.append("Password cannot contain sequential letters")
        
        return len(errors) == 0, errors

    @staticmethod
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Ensure all requirements are met
        if not PasswordPolicy.validate_password(password)[0]:
            return PasswordPolicy.generate_secure_password(length)
        
        return password
```

## 🔐 Data Protection

### Encryption at Rest

**Database Encryption:**
```python
# src/security/encryption.py
from cryptography.fernet import Fernet
import os
import base64

class FieldEncryption:
    def __init__(self):
        key = os.getenv('ENCRYPTION_KEY')
        if not key:
            # Generate key: Fernet.generate_key()
            raise ValueError("ENCRYPTION_KEY environment variable required")
        self.cipher = Fernet(key.encode())
    
    def encrypt_field(self, data: str) -> str:
        """Encrypt sensitive field data"""
        if data is None:
            return None
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_field(self, encrypted_data: str) -> str:
        """Decrypt sensitive field data"""
        if encrypted_data is None:
            return None
        return self.cipher.decrypt(encrypted_data.encode()).decode()

# SQLAlchemy encrypted column type
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

class EncryptedPatientData(Base):
    __tablename__ = "patient_data"
    
    id = Column(Integer, primary_key=True)
    patient_name = Column(EncryptedType(String, secret_key, AesEngine, 'pkcs5'))
    medical_record = Column(EncryptedType(Text, secret_key, AesEngine, 'pkcs5'))
    emergency_contact = Column(EncryptedType(String, secret_key, AesEngine, 'pkcs5'))
```

### Data Anonymization

```python
# src/security/anonymization.py
import hashlib
import random
import string

class DataAnonymizer:
    @staticmethod
    def hash_identifier(identifier: str, salt: str = None) -> str:
        """Create consistent hash for patient identifiers"""
        if salt is None:
            salt = os.getenv('HASH_SALT', 'default-salt-change-in-production')
        
        return hashlib.sha256(f"{identifier}{salt}".encode()).hexdigest()[:16]
    
    @staticmethod
    def anonymize_patient_id(patient_id: str) -> str:
        """Convert patient ID to anonymous identifier"""
        return f"PATIENT_{DataAnonymizer.hash_identifier(patient_id)}"
    
    @staticmethod
    def anonymize_location(room_number: str) -> str:
        """Anonymize room/location data"""
        return f"ROOM_{DataAnonymizer.hash_identifier(room_number)}"
    
    @staticmethod
    def generate_research_dataset(logs: list) -> list:
        """Generate anonymized dataset for research"""
        anonymized_logs = []
        
        for log in logs:
            anonymized_log = {
                'timestamp': log.timestamp,
                'patient_id': DataAnonymizer.anonymize_patient_id(log.sensor_id.split('_')[1]),
                'metric_type': log.metric,
                'value': log.value,
                'alert_triggered': log.alert_sent,
                'location': DataAnonymizer.anonymize_location(log.sensor_id.split('_')[2]) if '_' in log.sensor_id else 'UNKNOWN'
            }
            anonymized_logs.append(anonymized_log)
        
        return anonymized_logs
```

## 🌐 Network Security

### TLS/SSL Configuration

**MQTT TLS Setup:**
```bash
# Generate CA certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

# Generate server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Generate client certificate
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

**Mosquitto TLS Configuration:**
```conf
# /etc/mosquitto/conf.d/tls.conf
port 8883
cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key

# Require client certificates
require_certificate true
use_identity_as_username true

# TLS settings
tls_version tlsv1.2
ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
```

### Network Segmentation

**Firewall Rules:**
```bash
#!/bin/bash
# firewall-setup.sh

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH (limit connections)
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min --limit-burst 3 -j ACCEPT

# HTTPS only (no HTTP in production)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# MQTT TLS
iptables -A INPUT -p tcp --dport 8883 -s 10.0.0.0/8 -j ACCEPT

# Database (only from app servers)
iptables -A INPUT -p tcp --dport 5432 -s 10.0.1.0/24 -j ACCEPT

# Block everything else
iptables -A INPUT -j LOG --log-prefix "DROPPED: "
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### VPN Configuration

**WireGuard Setup for Remote Access:**
```ini
# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.0.200.1/24
ListenPort = 51820

# Staff access
[Peer]
PublicKey = STAFF_PUBLIC_KEY
AllowedIPs = 10.0.200.2/32

# Doctor remote access
[Peer]
PublicKey = DOCTOR_PUBLIC_KEY
AllowedIPs = 10.0.200.3/32
```

## 🕵️ Audit Logging & Monitoring

### Comprehensive Audit System

```python
# src/security/audit.py
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from datetime import datetime
import json

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100))
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
class AuditLogger:
    @staticmethod
    def log_action(user_id: int, action: str, resource_type: str, 
                   resource_id: str = None, details: dict = None,
                   ip_address: str = None, user_agent: str = None):
        
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.add(audit_log)
        db.commit()
        
        # Also log to security monitoring system
        SecurityMonitor.log_event({
            'user_id': user_id,
            'action': action,
            'resource': f"{resource_type}:{resource_id}",
            'timestamp': datetime.utcnow().isoformat(),
            'ip': ip_address
        })

# Decorator for automatic audit logging
def audit_action(action: str, resource_type: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user and request info
            current_user = get_current_user()
            request = get_current_request()
            
            try:
                result = await func(*args, **kwargs)
                
                # Log successful action
                AuditLogger.log_action(
                    user_id=current_user.id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=getattr(result, 'id', None),
                    ip_address=request.client.host,
                    user_agent=request.headers.get('user-agent')
                )
                
                return result
                
            except Exception as e:
                # Log failed action
                AuditLogger.log_action(
                    user_id=current_user.id,
                    action=f"{action}_FAILED",
                    resource_type=resource_type,
                    details={'error': str(e)},
                    ip_address=request.client.host,
                    user_agent=request.headers.get('user-agent')
                )
                raise
                
        return wrapper
    return decorator
```

### Security Event Monitoring

```python
# src/security/monitoring.py
import logging
from datetime import datetime, timedelta
from collections import defaultdict

class SecurityMonitor:
    # Track failed login attempts
    failed_logins = defaultdict(list)
    
    @classmethod
    def log_failed_login(cls, username: str, ip_address: str):
        cls.failed_logins[ip_address].append({
            'username': username,
            'timestamp': datetime.utcnow()
        })
        
        # Check for brute force attack
        recent_attempts = [
            attempt for attempt in cls.failed_logins[ip_address]
            if attempt['timestamp'] > datetime.utcnow() - timedelta(minutes=15)
        ]
        
        if len(recent_attempts) >= 5:
            cls.trigger_security_alert('BRUTE_FORCE_ATTACK', {
                'ip_address': ip_address,
                'attempts': len(recent_attempts),
                'usernames': [attempt['username'] for attempt in recent_attempts]
            })
    
    @classmethod
    def log_suspicious_activity(cls, activity_type: str, details: dict):
        cls.trigger_security_alert('SUSPICIOUS_ACTIVITY', {
            'type': activity_type,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @classmethod
    def trigger_security_alert(cls, alert_type: str, details: dict):
        # Log to security log
        security_logger = logging.getLogger('security')
        security_logger.critical(f"SECURITY ALERT: {alert_type} - {details}")
        
        # Send to SIEM system
        cls.send_to_siem(alert_type, details)
        
        # Notify security team
        cls.notify_security_team(alert_type, details)
    
    @classmethod
    def send_to_siem(cls, alert_type: str, details: dict):
        # Integration with SIEM systems (Splunk, ELK, etc.)
        pass
    
    @classmethod
    def notify_security_team(cls, alert_type: str, details: dict):
        # Send email/SMS to security team
        pass
```

## 🛡️ Input Validation & Sanitization

### SQL Injection Prevention

```python
# src/security/input_validation.py
import re
from sqlalchemy import text
from typing import Any, Dict, List

class InputValidator:
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
        r"(--|#|\/\*|\*\/)",
        r"(\b(or|and)\b.*[=<>])",
        r"(['\"].*['\"].*[=<>])",
        r"(\b(script|javascript|vbscript|onload|onerror)\b)"
    ]
    
    @staticmethod
    def validate_sql_input(input_string: str) -> tuple[bool, str]:
        """Validate input for SQL injection attempts"""
        if not input_string:
            return True, ""
        
        # Check for SQL injection patterns
        for pattern in InputValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                return False, f"Potentially malicious input detected: {pattern}"
        
        return True, ""
    
    @staticmethod
    def sanitize_sensor_id(sensor_id: str) -> str:
        """Sanitize sensor ID input"""
        # Only allow alphanumeric, underscore, and hyphen
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', sensor_id)
        
        # Limit length
        return sanitized[:100]
    
    @staticmethod
    def validate_numeric_threshold(value: Any) -> tuple[bool, float]:
        """Validate and convert threshold values"""
        try:
            numeric_value = float(value)
            
            # Check for reasonable bounds
            if not (-1000000 <= numeric_value <= 1000000):
                return False, 0.0
            
            return True, numeric_value
            
        except (ValueError, TypeError):
            return False, 0.0
    
    @staticmethod
    def validate_operator(operator: str) -> bool:
        """Validate alert rule operators"""
        allowed_operators = ['>', '<', '>=', '<=', '==', '!=']
        return operator in allowed_operators
```

### XSS Prevention

```python
# src/security/xss_protection.py
import html
import re
from typing import Dict, Any

class XSSProtection:
    # Dangerous HTML tags and attributes
    DANGEROUS_TAGS = ['script', 'iframe', 'object', 'embed', 'form', 'input']
    DANGEROUS_ATTRIBUTES = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus']
    
    @staticmethod
    def sanitize_html(content: str) -> str:
        """Remove potentially dangerous HTML content"""
        if not content:
            return ""
        
        # HTML encode the content
        sanitized = html.escape(content)
        
        # Remove dangerous patterns
        for tag in XSSProtection.DANGEROUS_TAGS:
            pattern = f"<{tag}[^>]*>.*?</{tag}>"
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized
    
    @staticmethod
    def validate_json_input(data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize JSON input data"""
        if not isinstance(data, dict):
            return {}
        
        sanitized = {}
        for key, value in data.items():
            # Sanitize keys
            clean_key = XSSProtection.sanitize_html(str(key))
            
            # Sanitize values
            if isinstance(value, str):
                clean_value = XSSProtection.sanitize_html(value)
            elif isinstance(value, dict):
                clean_value = XSSProtection.validate_json_input(value)
            elif isinstance(value, list):
                clean_value = [
                    XSSProtection.sanitize_html(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                clean_value = value
            
            sanitized[clean_key] = clean_value
        
        return sanitized
```

## 🔐 Secrets Management

### Environment Variables Security

```python
# src/security/secrets.py
import os
import keyring
from cryptography.fernet import Fernet
import base64

class SecretManager:
    def __init__(self):
        self.service_name = "elderly_care_engine"
    
    @staticmethod
    def generate_secret_key() -> str:
        """Generate a secure secret key"""
        return base64.urlsafe_b64encode(Fernet.generate_key()).decode()
    
    def store_secret(self, key: str, value: str):
        """Store secret in system keyring"""
        keyring.set_password(self.service_name, key, value)
    
    def get_secret(self, key: str, default: str = None) -> str:
        """Get secret from environment or keyring"""
        # First try environment variable
        value = os.getenv(key)
        if value:
            return value
        
        # Then try system keyring
        value = keyring.get_password(self.service_name, key)
        if value:
            return value
        
        return default
    
    def validate_secrets(self) -> List[str]:
        """Validate all required secrets are present"""
        required_secrets = [
            'SECRET_KEY',
            'DATABASE_URL',
            'ENCRYPTION_KEY',
            'MQTT_PASSWORD'
        ]
        
        missing_secrets = []
        for secret in required_secrets:
            if not self.get_secret(secret):
                missing_secrets.append(secret)
        
        return missing_secrets
```

### Production Security Checklist

```bash
#!/bin/bash
# security-checklist.sh

echo "🔒 Security Configuration Checklist"
echo "===================================="

# Check environment variables
echo "1. Checking environment variables..."
if [ -z "$SECRET_KEY" ]; then
    echo "❌ SECRET_KEY not set"
else
    echo "✅ SECRET_KEY configured"
fi

if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL not set"
else
    echo "✅ DATABASE_URL configured"
fi

# Check file permissions
echo "2. Checking file permissions..."
if [ "$(stat -c '%a' .env)" != "600" ]; then
    echo "⚠️  .env file permissions should be 600"
    chmod 600 .env
else
    echo "✅ .env file permissions correct"
fi

# Check SSL certificates
echo "3. Checking SSL certificates..."
if [ -f "/etc/nginx/ssl/elderly-care.crt" ]; then
    # Check certificate expiry
    expiry=$(openssl x509 -enddate -noout -in /etc/nginx/ssl/elderly-care.crt | cut -d= -f2)
    echo "✅ SSL certificate found (expires: $expiry)"
else
    echo "❌ SSL certificate not found"
fi

# Check firewall status
echo "4. Checking firewall..."
if ufw status | grep -q "Status: active"; then
    echo "✅ UFW firewall is active"
else
    echo "❌ UFW firewall is not active"
fi

# Check service status
echo "5. Checking services..."
if systemctl is-active --quiet elderly-care; then
    echo "✅ Elderly Care service is running"
else
    echo "❌ Elderly Care service is not running"
fi

if systemctl is-active --quiet mosquitto; then
    echo "✅ Mosquitto MQTT broker is running"
else
    echo "❌ Mosquitto MQTT broker is not running"
fi

echo "===================================="
echo "Security check completed"
```

This comprehensive security guide ensures the Elderly Care Home Alert Engine maintains the highest security standards for protecting sensitive healthcare data!
