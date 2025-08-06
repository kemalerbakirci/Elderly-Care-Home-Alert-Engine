# 🚀 Deployment Guide

Complete guide for deploying the Elderly Care Home Alert Engine to production environments.

## 🎯 Deployment Options

### 1. Docker Deployment (Recommended)

#### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- 2GB+ RAM
- 10GB+ Storage

#### Quick Start with Docker

**Create Docker Compose file:**

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Main Application
  elderly-care-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:///./data/elderly_care.db
      - MQTT_HOST=mosquitto
      - MQTT_PORT=1883
      - SECRET_KEY=${SECRET_KEY:-your-super-secret-key-change-in-production}
      - ENVIRONMENT=production
    volumes:
      - ./data:/app/data
    depends_on:
      - mosquitto
    restart: unless-stopped
    networks:
      - elderly-care-network

  # MQTT Broker
  mosquitto:
    image: eclipse-mosquitto:2.0
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - ./mosquitto/config:/mosquitto/config
      - ./mosquitto/data:/mosquitto/data
      - ./mosquitto/log:/mosquitto/log
    restart: unless-stopped
    networks:
      - elderly-care-network

  # Database (PostgreSQL for production)
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=elderly_care
      - POSTGRES_USER=elderly_care_user
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-change-this-password}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - elderly-care-network

  # Redis for Caching (Optional)
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped
    networks:
      - elderly-care-network

  # Reverse Proxy with SSL
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - elderly-care-api
    restart: unless-stopped
    networks:
      - elderly-care-network

volumes:
  postgres_data:
  redis_data:

networks:
  elderly-care-network:
    driver: bridge
```

**Create Dockerfile:**

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY test_alerts.py .

# Create data directory
RUN mkdir -p /app/data

# Create non-root user
RUN useradd -m -u 1000 elderly_care && chown -R elderly_care:elderly_care /app
USER elderly_care

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Start application
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

**Deploy:**

```bash
# Clone repository
git clone https://github.com/kemalerbakirci/Elderly-Care-Home-Alert-Engine.git
cd Elderly-Care-Home-Alert-Engine

# Create environment file
cp .env.example .env
# Edit .env with your production values

# Create required directories
mkdir -p mosquitto/{config,data,log}
mkdir -p nginx/ssl
mkdir -p data

# Create Mosquitto config
cat > mosquitto/config/mosquitto.conf << EOF
persistence true
persistence_location /mosquitto/data/
log_dest file /mosquitto/log/mosquitto.log
listener 1883
allow_anonymous true
EOF

# Start services
docker-compose up -d

# Check status
docker-compose ps
```

### 2. Cloud Deployment

#### AWS ECS Deployment

**ECS Task Definition:**

```json
{
  "family": "elderly-care-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "elderly-care-api",
      "image": "your-account.dkr.ecr.region.amazonaws.com/elderly-care:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DATABASE_URL",
          "value": "postgresql://user:pass@rds-endpoint:5432/elderly_care"
        },
        {
          "name": "MQTT_HOST", 
          "value": "your-iot-core-endpoint"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/elderly-care",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Azure Container Instances

```yaml
# azure-deployment.yml
apiVersion: 2019-12-01
location: eastus
name: elderly-care-container-group
properties:
  containers:
  - name: elderly-care-api
    properties:
      image: elderlycare.azurecr.io/elderly-care:latest
      resources:
        requests:
          cpu: 1.0
          memoryInGB: 2.0
      ports:
      - port: 8000
        protocol: TCP
      environmentVariables:
      - name: DATABASE_URL
        value: postgresql://server:5432/elderly_care
      - name: MQTT_HOST
        value: your-iot-hub.azure-devices.net
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 8000
```

#### Google Cloud Run

```yaml
# service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: elderly-care-api
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/memory: "2Gi"
        run.googleapis.com/cpu: "1000m"
    spec:
      containers:
      - image: gcr.io/PROJECT-ID/elderly-care:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          value: postgresql://user:pass@/elderly_care?host=/cloudsql/PROJECT:REGION:INSTANCE
        - name: MQTT_HOST
          value: mqtt.googleapis.com
        resources:
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

### 3. Traditional Server Deployment

#### Ubuntu 22.04 Setup

```bash
#!/bin/bash
# deploy.sh

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.11
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install MQTT Broker
sudo apt install -y mosquitto mosquitto-clients

# Install Nginx
sudo apt install -y nginx

# Install Redis
sudo apt install -y redis-server

# Create application user
sudo useradd -m -s /bin/bash elderly_care

# Create application directory
sudo mkdir -p /opt/elderly-care
sudo chown elderly_care:elderly_care /opt/elderly-care

# Switch to application user
sudo -u elderly_care bash << 'EOF'
cd /opt/elderly-care

# Clone repository
git clone https://github.com/kemalerbakirci/Elderly-Care-Home-Alert-Engine.git .

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create environment file
cp .env.example .env
EOF

# Configure PostgreSQL
sudo -u postgres psql << 'EOF'
CREATE DATABASE elderly_care;
CREATE USER elderly_care_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE elderly_care TO elderly_care_user;
\q
EOF

# Configure systemd service
sudo tee /etc/systemd/system/elderly-care.service > /dev/null << 'EOF'
[Unit]
Description=Elderly Care Home Alert Engine
After=network.target postgresql.service

[Service]
Type=exec
User=elderly_care
Group=elderly_care
WorkingDirectory=/opt/elderly-care
Environment=PATH=/opt/elderly-care/venv/bin
ExecStart=/opt/elderly-care/venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Start and enable service
sudo systemctl daemon-reload
sudo systemctl enable elderly-care
sudo systemctl start elderly-care
```

## 🔧 Configuration

### Environment Variables

```bash
# .env
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/elderly_care

# MQTT Configuration  
MQTT_HOST=localhost
MQTT_PORT=1883
MQTT_USERNAME=mqtt_user
MQTT_PASSWORD=mqtt_password
MQTT_USE_TLS=false

# Security
SECRET_KEY=your-super-secret-key-minimum-32-characters
ACCESS_TOKEN_EXPIRE_MINUTES=30
HASH_ALGORITHM=HS256

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false
ENVIRONMENT=production

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/elderly-care/app.log

# Redis (Optional)
REDIS_URL=redis://localhost:6379/0

# Email Notifications (Optional)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@yourfacility.com
SMTP_PASSWORD=app_password

# Monitoring
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
METRICS_ENABLED=true
```

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/elderly-care
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/elderly-care.crt;
    ssl_certificate_key /etc/nginx/ssl/elderly-care.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    # Main Application
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket Support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # MQTT WebSocket Proxy
    location /mqtt {
        proxy_pass http://localhost:9001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }

    # Static Files (if any)
    location /static/ {
        alias /opt/elderly-care/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Health Check
    location /health {
        access_log off;
        proxy_pass http://localhost:8000/health;
    }
}
```

## 🔒 Security Configuration

### SSL/TLS Setup

```bash
# Generate SSL certificate with Let's Encrypt
sudo apt install -y certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Firewall Configuration

```bash
# UFW Firewall
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 1883/tcp  # MQTT
sudo ufw deny 8000/tcp   # Block direct API access
```

### Database Security

```sql
-- PostgreSQL security
-- Create read-only user for monitoring
CREATE USER monitoring WITH PASSWORD 'monitoring_password';
GRANT CONNECT ON DATABASE elderly_care TO monitoring;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO monitoring;

-- Backup user
CREATE USER backup_user WITH PASSWORD 'backup_password';
GRANT CONNECT ON DATABASE elderly_care TO backup_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO backup_user;
```

## 📊 Monitoring & Logging

### Application Monitoring

```python
# monitoring.py
from prometheus_client import Counter, Histogram, generate_latest
import time

# Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')
MQTT_MESSAGES = Counter('mqtt_messages_total', 'Total MQTT messages', ['topic'])
ALERTS_SENT = Counter('alerts_sent_total', 'Total alerts sent', ['type'])

# Middleware for FastAPI
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    
    response = await call_next(request)
    
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path
    ).inc()
    
    REQUEST_DURATION.observe(time.time() - start_time)
    
    return response

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### Log Configuration

```python
# logging_config.py
import logging
import logging.handlers
import os

def setup_logging():
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    log_file = os.getenv('LOG_FILE', '/var/log/elderly-care/app.log')
    
    # Create log directory
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            ),
            logging.StreamHandler()
        ]
    )
```

## 🔄 Backup & Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/opt/backups/elderly-care"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="elderly_care"

# Create backup directory
mkdir -p $BACKUP_DIR

# PostgreSQL backup
pg_dump -h localhost -U elderly_care_user $DB_NAME | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# Keep only last 30 days of backups
find $BACKUP_DIR -name "db_backup_*.sql.gz" -mtime +30 -delete

# Upload to S3 (optional)
# aws s3 cp $BACKUP_DIR/db_backup_$DATE.sql.gz s3://your-backup-bucket/elderly-care/
```

### Disaster Recovery

```bash
# restore.sh
#!/bin/bash

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop application
sudo systemctl stop elderly-care

# Restore database
gunzip -c $BACKUP_FILE | psql -h localhost -U elderly_care_user elderly_care

# Start application
sudo systemctl start elderly-care

echo "Recovery completed"
```

## 📈 Scaling

### Horizontal Scaling

```yaml
# kubernetes-deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elderly-care-api
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
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: elderly-care-service
spec:
  selector:
    app: elderly-care-api
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

### Load Balancer Configuration

```nginx
# load-balancer.conf
upstream elderly_care_backend {
    least_conn;
    server 10.0.1.10:8000 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8000 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    
    location / {
        proxy_pass http://elderly_care_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    }
}
```

This deployment guide provides comprehensive instructions for deploying the Elderly Care Home Alert Engine in various environments, from development to production scale!
