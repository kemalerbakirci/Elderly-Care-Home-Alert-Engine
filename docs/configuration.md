# ⚙️ Configuration Guide

Comprehensive configuration documentation for the Elderly Care Home Alert Engine.

## 🎯 Configuration Overview

The system supports multiple configuration methods to accommodate different deployment environments:

1. **Environment Variables** (Recommended for production)
2. **Configuration Files** (Development and testing)
3. **Docker Compose Variables** (Container deployments)
4. **Kubernetes ConfigMaps/Secrets** (Kubernetes deployments)

## 📁 Configuration Structure

```
config/
├── .env.example              # Example environment variables
├── development.yaml          # Development settings
├── production.yaml           # Production settings
├── testing.yaml             # Test environment settings
└── docker/
    ├── docker-compose.yml    # Docker configuration
    └── .env.docker          # Docker environment variables
```

## 🔧 Environment Variables

### Core Application Settings

```bash
# .env

# ====================================
# APPLICATION CONFIGURATION
# ====================================

# Environment (development, testing, production)
ENVIRONMENT=production

# Application host and port
API_HOST=0.0.0.0
API_PORT=8000

# Debug mode (never enable in production)
DEBUG=false

# Application version
APP_VERSION=1.0.0

# Timezone for timestamps
TIMEZONE=UTC

# ====================================
# DATABASE CONFIGURATION
# ====================================

# Primary database URL
DATABASE_URL=postgresql://elderly_care_user:secure_password@localhost:5432/elderly_care

# Database connection pool settings
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600

# Database SSL settings
DB_SSL_MODE=require
DB_SSL_CERT_PATH=/etc/ssl/certs/client-cert.pem
DB_SSL_KEY_PATH=/etc/ssl/private/client-key.pem
DB_SSL_CA_PATH=/etc/ssl/certs/ca-cert.pem

# ====================================
# SECURITY CONFIGURATION
# ====================================

# JWT Secret Key (MUST be changed in production)
SECRET_KEY=your-super-secret-key-minimum-32-characters-change-in-production

# JWT Settings
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
HASH_ALGORITHM=HS256

# Encryption key for sensitive data
ENCRYPTION_KEY=your-encryption-key-for-database-fields

# Password policy
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_MAX_AGE_DAYS=90

# ====================================
# MQTT CONFIGURATION
# ====================================

# MQTT Broker settings
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_USERNAME=mqtt_user
MQTT_PASSWORD=mqtt_secure_password

# MQTT TLS/SSL settings
MQTT_USE_TLS=false
MQTT_TLS_CA_PATH=/etc/mqtt/certs/ca.crt
MQTT_TLS_CERT_PATH=/etc/mqtt/certs/client.crt
MQTT_TLS_KEY_PATH=/etc/mqtt/certs/client.key
MQTT_TLS_INSECURE=false

# MQTT QoS levels
MQTT_SENSOR_QOS=1
MQTT_ALERT_QOS=2
MQTT_KEEPALIVE=60

# MQTT topics
MQTT_SENSOR_TOPIC_PREFIX=sensors
MQTT_ALERT_TOPIC_PREFIX=alerts
MQTT_SYSTEM_TOPIC_PREFIX=system

# ====================================
# REDIS CONFIGURATION (Optional)
# ====================================

# Redis URL for caching and rate limiting
REDIS_URL=redis://localhost:6379/0

# Redis settings
REDIS_MAX_CONNECTIONS=50
REDIS_RETRY_ON_TIMEOUT=true
REDIS_SOCKET_CONNECT_TIMEOUT=5
REDIS_SOCKET_TIMEOUT=5

# Cache settings
CACHE_DEFAULT_TIMEOUT=300
CACHE_RULES_TIMEOUT=3600
CACHE_USER_TIMEOUT=1800

# ====================================
# LOGGING CONFIGURATION
# ====================================

# Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL=INFO

# Log file path
LOG_FILE=/var/log/elderly-care/app.log

# Log rotation
LOG_MAX_BYTES=10485760  # 10MB
LOG_BACKUP_COUNT=5

# Structured logging
LOG_FORMAT=json
LOG_INCLUDE_TRACE_ID=true

# External logging
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
ELASTICSEARCH_URL=http://localhost:9200

# ====================================
# MONITORING & METRICS
# ====================================

# Prometheus metrics
METRICS_ENABLED=true
METRICS_PORT=9090

# Health check settings
HEALTH_CHECK_TIMEOUT=10
HEALTH_CHECK_INTERVAL=30

# Performance monitoring
ENABLE_PERFORMANCE_MONITORING=true
SLOW_QUERY_THRESHOLD=1.0

# ====================================
# EMAIL NOTIFICATIONS
# ====================================

# SMTP settings for email alerts
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=alerts@yourfacility.com
SMTP_PASSWORD=app_specific_password

# Email settings
EMAIL_FROM=Elderly Care System <alerts@yourfacility.com>
EMAIL_TEMPLATES_DIR=/app/templates/email

# ====================================
# ALERT CONFIGURATION
# ====================================

# Alert settings
ALERT_COOLDOWN_SECONDS=300
ALERT_MAX_RETRIES=3
ALERT_BATCH_SIZE=10

# Emergency alert settings
EMERGENCY_ALERT_TIMEOUT=30
EMERGENCY_ESCALATION_ENABLED=true
EMERGENCY_CONTACT_EMAIL=emergency@yourfacility.com
EMERGENCY_CONTACT_SMS=+1234567890

# ====================================
# RATE LIMITING
# ====================================

# API rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_BURST_SIZE=10

# Login attempt limiting
MAX_LOGIN_ATTEMPTS=5
LOGIN_LOCKOUT_DURATION=900  # 15 minutes

# ====================================
# FILE UPLOAD SETTINGS
# ====================================

# File upload limits
MAX_UPLOAD_SIZE=10485760  # 10MB
ALLOWED_EXTENSIONS=csv,xlsx,json
UPLOAD_DIRECTORY=/app/uploads

# ====================================
# BACKUP CONFIGURATION
# ====================================

# Backup settings
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *  # Daily at 2 AM
BACKUP_RETENTION_DAYS=30
BACKUP_S3_BUCKET=elderly-care-backups
BACKUP_S3_REGION=us-east-1

# ====================================
# DEVELOPMENT SETTINGS
# ====================================

# Development only settings
DEV_AUTO_RELOAD=true
DEV_MOCK_MQTT=false
DEV_MOCK_EMAIL=true
DEV_SEED_DATA=true
```

## 📋 Configuration Files

### Development Configuration

```yaml
# config/development.yaml
app:
  name: "Elderly Care Home Alert Engine"
  version: "1.0.0"
  environment: "development"
  debug: true
  
server:
  host: "127.0.0.1"
  port: 8000
  reload: true
  workers: 1

database:
  url: "sqlite:///./elderly_care_dev.db"
  echo: true  # Log all SQL queries
  pool_size: 5
  max_overflow: 10

mqtt:
  host: "localhost"
  port: 1883
  username: null
  password: null
  use_tls: false
  qos:
    sensors: 1
    alerts: 2
  topics:
    sensor_prefix: "sensors"
    alert_prefix: "alerts"

security:
  secret_key: "dev-secret-key-not-for-production"
  algorithm: "HS256"
  access_token_expire_minutes: 60  # Longer for development
  
logging:
  level: "DEBUG"
  format: "pretty"
  file: "./logs/development.log"
  
cache:
  enabled: false  # Disable caching in development
  
monitoring:
  metrics_enabled: false
  sentry_enabled: false

email:
  mock: true  # Use mock email backend
  
alerts:
  cooldown_seconds: 10  # Shorter cooldown for testing
  
development:
  auto_reload: true
  mock_sensors: true
  seed_data: true
```

### Production Configuration

```yaml
# config/production.yaml
app:
  name: "Elderly Care Home Alert Engine"
  version: "1.0.0"
  environment: "production"
  debug: false
  
server:
  host: "0.0.0.0"
  port: 8000
  reload: false
  workers: 4

database:
  url: "${DATABASE_URL}"
  echo: false
  pool_size: 20
  max_overflow: 30
  pool_timeout: 30
  pool_recycle: 3600
  ssl:
    mode: "require"
    ca_cert: "${DB_SSL_CA_PATH}"
    client_cert: "${DB_SSL_CERT_PATH}"
    client_key: "${DB_SSL_KEY_PATH}"

mqtt:
  host: "${MQTT_HOST}"
  port: "${MQTT_PORT}"
  username: "${MQTT_USERNAME}"
  password: "${MQTT_PASSWORD}"
  use_tls: true
  tls:
    ca_cert: "${MQTT_TLS_CA_PATH}"
    client_cert: "${MQTT_TLS_CERT_PATH}"
    client_key: "${MQTT_TLS_KEY_PATH}"
    insecure: false
  qos:
    sensors: 1
    alerts: 2
  keepalive: 60

security:
  secret_key: "${SECRET_KEY}"
  algorithm: "HS256"
  access_token_expire_minutes: 30
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_special: true
    max_age_days: 90

logging:
  level: "INFO"
  format: "json"
  file: "/var/log/elderly-care/app.log"
  rotation:
    max_bytes: 10485760  # 10MB
    backup_count: 5
  external:
    sentry_dsn: "${SENTRY_DSN}"
    elasticsearch_url: "${ELASTICSEARCH_URL}"

cache:
  enabled: true
  redis_url: "${REDIS_URL}"
  default_timeout: 300
  
monitoring:
  metrics_enabled: true
  metrics_port: 9090
  health_check_timeout: 10
  performance_monitoring: true
  slow_query_threshold: 1.0

email:
  smtp:
    host: "${SMTP_HOST}"
    port: "${SMTP_PORT}"
    use_tls: true
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
  from_address: "${EMAIL_FROM}"
  templates_dir: "/app/templates/email"

alerts:
  cooldown_seconds: 300
  max_retries: 3
  batch_size: 10
  emergency:
    timeout: 30
    escalation_enabled: true
    contact_email: "${EMERGENCY_CONTACT_EMAIL}"
    contact_sms: "${EMERGENCY_CONTACT_SMS}"

rate_limiting:
  enabled: true
  requests_per_minute: 60
  burst_size: 10
  login_attempts:
    max_attempts: 5
    lockout_duration: 900

backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention_days: 30
  s3:
    bucket: "${BACKUP_S3_BUCKET}"
    region: "${BACKUP_S3_REGION}"
```

### Testing Configuration

```yaml
# config/testing.yaml
app:
  name: "Elderly Care Home Alert Engine - Test"
  version: "1.0.0"
  environment: "testing"
  debug: true

server:
  host: "127.0.0.1"
  port: 8001
  workers: 1

database:
  url: "sqlite:///./test.db"
  echo: false
  
mqtt:
  host: "localhost"
  port: 1883
  mock: true  # Use mock MQTT client for testing

security:
  secret_key: "test-secret-key"
  access_token_expire_minutes: 5  # Short expiry for testing

logging:
  level: "WARNING"  # Reduce noise in tests
  file: "./logs/test.log"

cache:
  enabled: false

monitoring:
  metrics_enabled: false

email:
  mock: true

alerts:
  cooldown_seconds: 1  # Very short for testing
```

## 🐳 Docker Configuration

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  elderly-care-api:
    build: .
    ports:
      - "${API_PORT:-8000}:8000"
    environment:
      - DATABASE_URL=postgresql://elderly_care:${POSTGRES_PASSWORD}@postgres:5432/elderly_care
      - MQTT_HOST=mosquitto
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
      - ENVIRONMENT=production
    env_file:
      - .env
    volumes:
      - ./logs:/app/logs
      - ./uploads:/app/uploads
    depends_on:
      postgres:
        condition: service_healthy
      mosquitto:
        condition: service_started
      redis:
        condition: service_started
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - elderly-care

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=elderly_care
      - POSTGRES_USER=elderly_care
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U elderly_care"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - elderly-care

  mosquitto:
    image: eclipse-mosquitto:2.0
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - ./mosquitto/config:/mosquitto/config
      - ./mosquitto/data:/mosquitto/data
      - ./mosquitto/log:/mosquitto/log
      - mosquitto_data:/mosquitto/data
    restart: unless-stopped
    networks:
      - elderly-care

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped
    command: redis-server --appendonly yes
    networks:
      - elderly-care

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - nginx_cache:/var/cache/nginx
    depends_on:
      - elderly-care-api
    restart: unless-stopped
    networks:
      - elderly-care

volumes:
  postgres_data:
  mosquitto_data:
  redis_data:
  nginx_cache:

networks:
  elderly-care:
    driver: bridge
```

### Docker Environment Variables

```bash
# .env.docker

# Database
POSTGRES_PASSWORD=secure_production_password

# Application secrets
SECRET_KEY=your-super-secure-secret-key-for-production-32-chars-min
ENCRYPTION_KEY=your-encryption-key-for-sensitive-data

# MQTT
MQTT_USERNAME=elderly_care_mqtt
MQTT_PASSWORD=mqtt_secure_password

# Redis
REDIS_PASSWORD=redis_secure_password

# Email
SMTP_USERNAME=alerts@yourfacility.com
SMTP_PASSWORD=smtp_app_password

# Monitoring
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project

# Backup
BACKUP_S3_BUCKET=elderly-care-backups
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# SSL
SSL_CERT_PATH=/etc/nginx/ssl/cert.pem
SSL_KEY_PATH=/etc/nginx/ssl/key.pem
```

## ☸️ Kubernetes Configuration

### ConfigMap

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: elderly-care-config
  namespace: elderly-care
data:
  app_name: "Elderly Care Home Alert Engine"
  environment: "production"
  log_level: "INFO"
  
  # Database
  db_pool_size: "20"
  db_max_overflow: "30"
  
  # MQTT
  mqtt_host: "mosquitto-service"
  mqtt_port: "1883"
  mqtt_sensor_qos: "1"
  mqtt_alert_qos: "2"
  
  # Cache
  redis_url: "redis://redis-service:6379/0"
  cache_default_timeout: "300"
  
  # Monitoring
  metrics_enabled: "true"
  metrics_port: "9090"
  
  # Rate limiting
  rate_limit_enabled: "true"
  requests_per_minute: "60"
```

### Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: elderly-care-secrets
  namespace: elderly-care
type: Opaque
data:
  # Base64 encoded values
  secret_key: <base64-encoded-secret-key>
  database_url: <base64-encoded-database-url>
  encryption_key: <base64-encoded-encryption-key>
  mqtt_username: <base64-encoded-mqtt-username>
  mqtt_password: <base64-encoded-mqtt-password>
  smtp_username: <base64-encoded-smtp-username>
  smtp_password: <base64-encoded-smtp-password>
  sentry_dsn: <base64-encoded-sentry-dsn>
```

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elderly-care-api
  namespace: elderly-care
spec:
  replicas: 3
  selector:
    matchLabels:
      app: elderly-care-api
  template:
    metadata:
      labels:
        app: elderly-care-api
    spec:
      containers:
      - name: elderly-care-api
        image: elderly-care:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: elderly-care-config
        - secretRef:
            name: elderly-care-secrets
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: elderly-care-secrets
              key: database_url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: elderly-care-secrets
              key: secret_key
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 🔧 Configuration Validation

### Configuration Validator

```python
# src/config/validator.py
import os
import re
from typing import Dict, List, Any
from pydantic import BaseSettings, validator, Field

class AppConfig(BaseSettings):
    """Application configuration with validation."""
    
    # Application settings
    app_name: str = Field(default="Elderly Care Home Alert Engine")
    environment: str = Field(default="development", regex="^(development|testing|production)$")
    debug: bool = Field(default=False)
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000, ge=1000, le=65535)
    
    # Database settings
    database_url: str = Field(...)
    db_pool_size: int = Field(default=20, ge=1, le=100)
    db_max_overflow: int = Field(default=30, ge=0, le=100)
    
    # Security settings
    secret_key: str = Field(..., min_length=32)
    access_token_expire_minutes: int = Field(default=30, ge=5, le=1440)
    
    # MQTT settings
    mqtt_host: str = Field(default="localhost")
    mqtt_port: int = Field(default=1883, ge=1, le=65535)
    mqtt_username: str = Field(default="")
    mqtt_password: str = Field(default="")
    
    # Logging settings
    log_level: str = Field(default="INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_file: str = Field(default="/var/log/elderly-care/app.log")
    
    @validator('secret_key')
    def validate_secret_key(cls, v):
        if v == "change-this-in-production" and os.getenv('ENVIRONMENT') == 'production':
            raise ValueError('SECRET_KEY must be changed in production')
        return v
    
    @validator('database_url')
    def validate_database_url(cls, v):
        if not v.startswith(('postgresql://', 'sqlite:///')):
            raise ValueError('DATABASE_URL must be a valid PostgreSQL or SQLite URL')
        return v
    
    @validator('environment')
    def validate_environment_specific_settings(cls, v, values):
        if v == 'production':
            if values.get('debug', False):
                raise ValueError('DEBUG must be False in production')
            if not values.get('secret_key', '').startswith('prod-'):
                # In real production, you might want a different validation
                pass
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

def validate_configuration() -> Dict[str, Any]:
    """Validate current configuration and return validation results."""
    try:
        config = AppConfig()
        return {
            "valid": True,
            "config": config.dict(),
            "errors": []
        }
    except Exception as e:
        return {
            "valid": False,
            "config": None,
            "errors": [str(e)]
        }

def check_required_secrets() -> List[str]:
    """Check for required secrets in production."""
    required_secrets = [
        'SECRET_KEY',
        'DATABASE_URL',
        'ENCRYPTION_KEY'
    ]
    
    missing_secrets = []
    for secret in required_secrets:
        if not os.getenv(secret):
            missing_secrets.append(secret)
    
    return missing_secrets

def validate_file_permissions() -> Dict[str, bool]:
    """Validate file permissions for security."""
    checks = {}
    
    # Check .env file permissions
    env_file = '.env'
    if os.path.exists(env_file):
        stat_info = os.stat(env_file)
        # Should be readable only by owner (600)
        checks['env_file_secure'] = oct(stat_info.st_mode)[-3:] == '600'
    else:
        checks['env_file_secure'] = True  # File doesn't exist, no issue
    
    # Check log directory permissions
    log_dir = '/var/log/elderly-care'
    if os.path.exists(log_dir):
        stat_info = os.stat(log_dir)
        # Should be writable by application user
        checks['log_dir_writable'] = os.access(log_dir, os.W_OK)
    else:
        checks['log_dir_writable'] = False
    
    return checks
```

### Configuration CLI Tool

```python
# scripts/config_tool.py
#!/usr/bin/env python3
"""Configuration management CLI tool."""

import os
import sys
import argparse
import json
from pathlib import Path
from src.config.validator import validate_configuration, check_required_secrets, validate_file_permissions

def validate_config():
    """Validate current configuration."""
    print("🔍 Validating configuration...")
    
    result = validate_configuration()
    
    if result['valid']:
        print("✅ Configuration is valid")
        return True
    else:
        print("❌ Configuration validation failed:")
        for error in result['errors']:
            print(f"   - {error}")
        return False

def check_secrets():
    """Check for required secrets."""
    print("🔐 Checking required secrets...")
    
    missing = check_required_secrets()
    
    if not missing:
        print("✅ All required secrets are present")
        return True
    else:
        print("❌ Missing required secrets:")
        for secret in missing:
            print(f"   - {secret}")
        return False

def check_permissions():
    """Check file permissions."""
    print("🔒 Checking file permissions...")
    
    checks = validate_file_permissions()
    all_good = True
    
    for check, passed in checks.items():
        if passed:
            print(f"✅ {check}")
        else:
            print(f"❌ {check}")
            all_good = False
    
    return all_good

def generate_config_template():
    """Generate configuration template."""
    template = """# Elderly Care Home Alert Engine Configuration
# Copy this file to .env and customize for your environment

# ====================================
# APPLICATION CONFIGURATION
# ====================================
ENVIRONMENT=production
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false

# ====================================
# DATABASE CONFIGURATION
# ====================================
DATABASE_URL=postgresql://user:password@localhost:5432/elderly_care

# ====================================
# SECURITY CONFIGURATION
# ====================================
SECRET_KEY=change-this-to-a-secure-secret-key-minimum-32-characters
ENCRYPTION_KEY=change-this-to-a-secure-encryption-key

# ====================================
# MQTT CONFIGURATION
# ====================================
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_USERNAME=mqtt_user
MQTT_PASSWORD=mqtt_password

# ====================================
# LOGGING CONFIGURATION
# ====================================
LOG_LEVEL=INFO
LOG_FILE=/var/log/elderly-care/app.log

# Add more configuration as needed...
"""
    
    with open('.env.template', 'w') as f:
        f.write(template)
    
    print("✅ Configuration template generated: .env.template")

def main():
    parser = argparse.ArgumentParser(description="Configuration management tool")
    parser.add_argument("command", choices=[
        "validate", "check-secrets", "check-permissions", 
        "generate-template", "full-check"
    ])
    
    args = parser.parse_args()
    
    if args.command == "validate":
        success = validate_config()
    elif args.command == "check-secrets":
        success = check_secrets()
    elif args.command == "check-permissions":
        success = check_permissions()
    elif args.command == "generate-template":
        generate_config_template()
        success = True
    elif args.command == "full-check":
        print("🔧 Running full configuration check...\n")
        success = all([
            validate_config(),
            check_secrets(),
            check_permissions()
        ])
        
        if success:
            print("\n🎉 All configuration checks passed!")
        else:
            print("\n⚠️  Some configuration issues found. Please fix and run again.")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

### Usage Examples

```bash
# Validate configuration
python scripts/config_tool.py validate

# Check for missing secrets
python scripts/config_tool.py check-secrets

# Check file permissions
python scripts/config_tool.py check-permissions

# Run all checks
python scripts/config_tool.py full-check

# Generate configuration template
python scripts/config_tool.py generate-template
```

## 🚀 Configuration Best Practices

### 1. Environment-Specific Configurations

```bash
# Use different .env files for different environments
.env.development    # Development settings
.env.testing       # Test environment settings
.env.production    # Production settings
.env.local         # Local overrides (git ignored)
```

### 2. Secret Management

```bash
# Never commit secrets to git
echo ".env*" >> .gitignore
echo "config/secrets.yaml" >> .gitignore

# Use external secret management in production
# Examples:
# - AWS Secrets Manager
# - Azure Key Vault
# - HashiCorp Vault
# - Kubernetes Secrets
```

### 3. Configuration Hierarchy

```
1. Environment variables (highest priority)
2. Configuration files
3. Default values (lowest priority)
```

### 4. Validation and Monitoring

```python
# Always validate configuration on startup
@app.on_event("startup")
async def validate_startup_config():
    result = validate_configuration()
    if not result['valid']:
        raise RuntimeError(f"Invalid configuration: {result['errors']}")
```

This comprehensive configuration guide ensures proper setup and management of the Elderly Care Home Alert Engine across all deployment environments!
