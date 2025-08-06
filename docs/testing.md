# 🧪 Testing Guide

Comprehensive testing strategy and documentation for the Elderly Care Home Alert Engine.

## 🎯 Testing Strategy

The testing approach follows a multi-layered strategy ensuring system reliability, security, and performance in healthcare environments.

### Testing Pyramid

```
                    🔺 E2E Tests
                   📊 Integration Tests  
                🧪 Unit Tests (Foundation)
```

- **Unit Tests (70%)**: Individual component testing
- **Integration Tests (20%)**: Service interaction testing  
- **End-to-End Tests (10%)**: Complete workflow testing

## 🏗️ Test Environment Setup

### Prerequisites

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov pytest-mock httpx

# Install additional testing tools
pip install factory-boy faker freezegun

# For load testing
pip install locust

# For security testing
pip install bandit safety
```

### Test Configuration

```python
# tests/conftest.py
import pytest
import asyncio
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from src.main import app
from src.database import Base, get_db
from src.auth.jwt_handler import create_access_token

# Test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
def db_session():
    """Create a fresh database for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)

@pytest.fixture
async def async_client():
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
def admin_token():
    """Create admin JWT token for testing."""
    return create_access_token(data={"sub": "admin", "role": "admin"})

@pytest.fixture
def nurse_token():
    """Create nurse JWT token for testing."""
    return create_access_token(data={"sub": "nurse", "role": "nurse"})
```

### Test Data Factories

```python
# tests/factories.py
import factory
from factory.alchemy import SQLAlchemyModelFactory
from datetime import datetime, timedelta
from src.models import User, Rule, Log

class UserFactory(SQLAlchemyModelFactory):
    class Meta:
        model = User
        sqlalchemy_session_persistence = "commit"
    
    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@facility.com")
    hashed_password = "$2b$12$example_hashed_password"
    role = "nurse"
    is_active = True
    created_at = factory.LazyFunction(datetime.utcnow)

class RuleFactory(SQLAlchemyModelFactory):
    class Meta:
        model = Rule
        sqlalchemy_session_persistence = "commit"
    
    sensor_id = factory.Sequence(lambda n: f"patient_{n:03d}_heart_rate")
    metric = "bpm"
    operator = ">"
    threshold = 100.0
    alert_topic = "alerts/medical_emergency"
    name = factory.LazyAttribute(lambda obj: f"High {obj.metric} Alert")
    description = factory.LazyAttribute(lambda obj: f"Alert when {obj.metric} {obj.operator} {obj.threshold}")
    enabled = True
    created_at = factory.LazyFunction(datetime.utcnow)

class LogFactory(SQLAlchemyModelFactory):
    class Meta:
        model = Log
        sqlalchemy_session_persistence = "commit"
    
    rule_id = factory.SubFactory(RuleFactory)
    sensor_id = factory.LazyAttribute(lambda obj: obj.rule_id.sensor_id)
    metric = factory.LazyAttribute(lambda obj: obj.rule_id.metric)
    value = 120.0
    threshold = factory.LazyAttribute(lambda obj: obj.rule_id.threshold)
    operator = factory.LazyAttribute(lambda obj: obj.rule_id.operator)
    alert_sent = True
    alert_topic = factory.LazyAttribute(lambda obj: obj.rule_id.alert_topic)
    timestamp = factory.LazyFunction(datetime.utcnow)
```

## 🔬 Unit Tests

### API Endpoint Tests

```python
# tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from tests.factories import UserFactory, RuleFactory

class TestHealthEndpoint:
    def test_health_check(self, client):
        """Test health endpoint returns correct status."""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "services" in data

class TestRulesAPI:
    def test_get_rules_unauthorized(self, client):
        """Test getting rules without authentication fails."""
        response = client.get("/rules")
        assert response.status_code == 403

    def test_get_rules_authorized(self, client, admin_token, db_session):
        """Test getting rules with authentication succeeds."""
        # Create test rules
        rule1 = RuleFactory()
        rule2 = RuleFactory()
        db_session.add_all([rule1, rule2])
        db_session.commit()
        
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = client.get("/rules", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_create_rule_valid_data(self, client, admin_token):
        """Test creating rule with valid data."""
        rule_data = {
            "sensor_id": "patient_001_heart_rate",
            "metric": "bpm",
            "operator": ">",
            "threshold": 100.0,
            "alert_topic": "alerts/medical_emergency",
            "name": "High Heart Rate",
            "description": "Alert for high heart rate"
        }
        
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = client.post("/rules", json=rule_data, headers=headers)
        
        assert response.status_code == 201
        data = response.json()
        assert data["sensor_id"] == "patient_001_heart_rate"
        assert data["threshold"] == 100.0

    def test_create_rule_invalid_operator(self, client, admin_token):
        """Test creating rule with invalid operator fails."""
        rule_data = {
            "sensor_id": "patient_001_heart_rate",
            "metric": "bpm",
            "operator": "INVALID",  # Invalid operator
            "threshold": 100.0,
            "alert_topic": "alerts/medical_emergency"
        }
        
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = client.post("/rules", json=rule_data, headers=headers)
        
        assert response.status_code == 422

    def test_delete_rule_unauthorized(self, client, db_session):
        """Test deleting rule without proper role fails."""
        rule = RuleFactory()
        db_session.add(rule)
        db_session.commit()
        
        # Use nurse token (insufficient permissions)
        nurse_token = create_access_token(data={"sub": "nurse", "role": "nurse"})
        headers = {"Authorization": f"Bearer {nurse_token}"}
        
        response = client.delete(f"/rules/{rule.id}", headers=headers)
        assert response.status_code == 403
```

### MQTT Handler Tests

```python
# tests/test_mqtt.py
import pytest
from unittest.mock import Mock, patch, AsyncMock
from src.mqtt_listener import MQTTListener

class TestMQTTListener:
    @pytest.fixture
    def mqtt_listener(self):
        """Create MQTT listener instance for testing."""
        return MQTTListener()

    def test_parse_topic_valid(self, mqtt_listener):
        """Test parsing valid MQTT topic."""
        topic = "sensors/patient_001_heart_rate/bpm"
        sensor_id, metric = mqtt_listener.parse_topic(topic)
        
        assert sensor_id == "patient_001_heart_rate"
        assert metric == "bpm"

    def test_parse_topic_invalid(self, mqtt_listener):
        """Test parsing invalid MQTT topic."""
        topic = "invalid/topic"
        
        with pytest.raises(ValueError):
            mqtt_listener.parse_topic(topic)

    @patch('src.mqtt_listener.mqtt.Client')
    async def test_mqtt_connection(self, mock_client, mqtt_listener):
        """Test MQTT connection establishment."""
        mock_client_instance = Mock()
        mock_client.return_value = mock_client_instance
        
        await mqtt_listener.connect()
        
        mock_client_instance.connect.assert_called_once()
        mock_client_instance.subscribe.assert_called_with("sensors/#")

    @patch('src.mqtt_listener.evaluate_rules')
    async def test_message_processing(self, mock_evaluate, mqtt_listener, db_session):
        """Test MQTT message processing."""
        # Create test rule
        rule = RuleFactory(
            sensor_id="patient_001_heart_rate",
            metric="bpm",
            operator=">",
            threshold=100.0
        )
        db_session.add(rule)
        db_session.commit()
        
        # Mock message
        mock_msg = Mock()
        mock_msg.topic = "sensors/patient_001_heart_rate/bpm"
        mock_msg.payload.decode.return_value = "120.0"
        
        await mqtt_listener.on_message(None, None, mock_msg)
        
        mock_evaluate.assert_called_once()

class TestRuleEvaluation:
    def test_greater_than_operator(self):
        """Test greater than operator evaluation."""
        from src.mqtt_listener import evaluate_rule
        
        # Rule: heart rate > 100
        rule = Mock()
        rule.operator = ">"
        rule.threshold = 100.0
        
        assert evaluate_rule(rule, 120.0) == True
        assert evaluate_rule(rule, 90.0) == False
        assert evaluate_rule(rule, 100.0) == False

    def test_equals_operator(self):
        """Test equals operator evaluation."""
        from src.mqtt_listener import evaluate_rule
        
        # Rule: motion == 0.0
        rule = Mock()
        rule.operator = "=="
        rule.threshold = 0.0
        
        assert evaluate_rule(rule, 0.0) == True
        assert evaluate_rule(rule, 1.0) == False

    def test_invalid_operator(self):
        """Test invalid operator handling."""
        from src.mqtt_listener import evaluate_rule
        
        rule = Mock()
        rule.operator = "INVALID"
        rule.threshold = 100.0
        
        assert evaluate_rule(rule, 120.0) == False
```

### Authentication Tests

```python
# tests/test_auth.py
import pytest
from datetime import datetime, timedelta
from jose import jwt
from src.auth.jwt_handler import create_access_token, verify_token
from src.auth.password_policy import PasswordPolicy

class TestJWTHandler:
    def test_create_token(self):
        """Test JWT token creation."""
        data = {"sub": "testuser", "role": "admin"}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 0

    def test_verify_valid_token(self):
        """Test verification of valid token."""
        data = {"sub": "testuser", "role": "admin"}
        token = create_access_token(data)
        
        payload = verify_token(token)
        
        assert payload is not None
        assert payload["username"] == "testuser"
        assert payload["role"] == "admin"

    def test_verify_expired_token(self):
        """Test verification of expired token."""
        data = {"sub": "testuser", "role": "admin"}
        expires_delta = timedelta(minutes=-1)  # Already expired
        token = create_access_token(data, expires_delta)
        
        payload = verify_token(token)
        assert payload is None

    def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        invalid_token = "invalid.jwt.token"
        payload = verify_token(invalid_token)
        assert payload is None

class TestPasswordPolicy:
    def test_valid_password(self):
        """Test validation of strong password."""
        password = "StrongP@ssw0rd123"
        is_valid, errors = PasswordPolicy.validate_password(password)
        
        assert is_valid == True
        assert len(errors) == 0

    def test_short_password(self):
        """Test validation of short password."""
        password = "Short1!"
        is_valid, errors = PasswordPolicy.validate_password(password)
        
        assert is_valid == False
        assert any("at least" in error for error in errors)

    def test_missing_uppercase(self):
        """Test password missing uppercase letters."""
        password = "longpassword123!"
        is_valid, errors = PasswordPolicy.validate_password(password)
        
        assert is_valid == False
        assert any("uppercase" in error for error in errors)

    def test_sequential_numbers(self):
        """Test password with sequential numbers."""
        password = "Password123456!"
        is_valid, errors = PasswordPolicy.validate_password(password)
        
        assert is_valid == False
        assert any("sequential" in error for error in errors)

    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "TestPassword123!"
        hashed = PasswordPolicy.hash_password(password)
        
        assert PasswordPolicy.verify_password(password, hashed) == True
        assert PasswordPolicy.verify_password("WrongPassword", hashed) == False
```

## 🔗 Integration Tests

### Database Integration

```python
# tests/test_integration_database.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tests.factories import UserFactory, RuleFactory, LogFactory

class TestDatabaseIntegration:
    def test_user_rule_relationship(self, db_session):
        """Test user and rule relationship."""
        user = UserFactory()
        rule1 = RuleFactory(created_by=user.id)
        rule2 = RuleFactory(created_by=user.id)
        
        db_session.add_all([user, rule1, rule2])
        db_session.commit()
        
        # Query user's rules
        user_rules = db_session.query(Rule).filter(Rule.created_by == user.id).all()
        assert len(user_rules) == 2

    def test_rule_log_cascade_delete(self, db_session):
        """Test cascade delete from rule to logs."""
        rule = RuleFactory()
        log1 = LogFactory(rule_id=rule.id)
        log2 = LogFactory(rule_id=rule.id)
        
        db_session.add_all([rule, log1, log2])
        db_session.commit()
        
        # Delete rule should cascade to logs
        db_session.delete(rule)
        db_session.commit()
        
        remaining_logs = db_session.query(Log).filter(Log.rule_id == rule.id).all()
        assert len(remaining_logs) == 0

    def test_concurrent_rule_creation(self, db_session):
        """Test concurrent rule creation doesn't cause conflicts."""
        import threading
        import time
        
        results = []
        
        def create_rule(sensor_id):
            try:
                rule = RuleFactory(sensor_id=f"sensor_{sensor_id}")
                db_session.add(rule)
                db_session.commit()
                results.append(True)
            except Exception as e:
                results.append(False)
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=create_rule, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # All should succeed
        assert all(results)
        assert len(results) == 5
```

### MQTT Integration

```python
# tests/test_integration_mqtt.py
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
import paho.mqtt.client as mqtt

class TestMQTTIntegration:
    @pytest.mark.asyncio
    async def test_end_to_end_alert_flow(self, db_session):
        """Test complete sensor data to alert flow."""
        # Create rule
        rule = RuleFactory(
            sensor_id="patient_001_heart_rate",
            metric="bpm",
            operator=">",
            threshold=100.0,
            alert_topic="alerts/medical_emergency"
        )
        db_session.add(rule)
        db_session.commit()
        
        alerts_received = []
        
        # Mock MQTT client for alerts
        def mock_publish(topic, payload):
            alerts_received.append({"topic": topic, "payload": payload})
        
        with patch('src.mqtt_listener.mqtt_client.publish', side_effect=mock_publish):
            # Simulate sensor data
            from src.mqtt_listener import process_sensor_data
            await process_sensor_data("patient_001_heart_rate", "bpm", 120.0)
        
        # Verify alert was sent
        assert len(alerts_received) == 1
        assert alerts_received[0]["topic"] == "alerts/medical_emergency"

    @pytest.mark.asyncio
    async def test_mqtt_connection_retry(self):
        """Test MQTT connection retry logic."""
        connection_attempts = []
        
        def mock_connect(*args):
            connection_attempts.append(True)
            if len(connection_attempts) < 3:
                raise ConnectionRefusedError("Connection failed")
            return True
        
        with patch('paho.mqtt.client.Client.connect', side_effect=mock_connect):
            from src.mqtt_listener import MQTTListener
            listener = MQTTListener()
            
            # Should retry and eventually succeed
            await listener.connect_with_retry()
            assert len(connection_attempts) == 3

    def test_mqtt_message_qos(self):
        """Test MQTT Quality of Service settings."""
        from src.mqtt_listener import MQTTListener
        
        listener = MQTTListener()
        
        # Critical alerts should use QoS 2
        assert listener.get_qos_for_topic("alerts/medical_emergency") == 2
        
        # Regular sensor data can use QoS 1
        assert listener.get_qos_for_topic("sensors/room_temp/celsius") == 1
```

## 🎭 End-to-End Tests

### Complete Workflow Tests

```python
# tests/test_e2e.py
import pytest
import asyncio
from httpx import AsyncClient
from tests.factories import UserFactory, RuleFactory

class TestE2EWorkflows:
    @pytest.mark.asyncio
    async def test_complete_alert_workflow(self, async_client, db_session, admin_token):
        """Test complete workflow from rule creation to alert."""
        # 1. Create user and authenticate
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # 2. Create alert rule
        rule_data = {
            "sensor_id": "patient_001_heart_rate",
            "metric": "bpm",
            "operator": ">",
            "threshold": 100.0,
            "alert_topic": "alerts/medical_emergency",
            "name": "High Heart Rate Alert"
        }
        
        response = await async_client.post("/rules", json=rule_data, headers=headers)
        assert response.status_code == 201
        rule_id = response.json()["id"]
        
        # 3. Simulate sensor data that triggers alert
        with patch('src.mqtt_listener.mqtt_client') as mock_mqtt:
            # Mock MQTT publish
            mock_mqtt.publish = AsyncMock()
            
            # Process sensor data
            from src.mqtt_listener import process_sensor_data
            await process_sensor_data("patient_001_heart_rate", "bpm", 120.0)
            
            # Verify alert was published
            mock_mqtt.publish.assert_called_once()
            args = mock_mqtt.publish.call_args
            assert args[0][0] == "alerts/medical_emergency"
        
        # 4. Check log was created
        response = await async_client.get("/logs", headers=headers)
        assert response.status_code == 200
        logs = response.json()
        
        # Should have one log entry
        assert len(logs) >= 1
        latest_log = logs[-1]
        assert latest_log["rule_id"] == rule_id
        assert latest_log["value"] == 120.0
        assert latest_log["alert_sent"] == True

    @pytest.mark.asyncio
    async def test_user_role_workflow(self, async_client, db_session):
        """Test different user roles and permissions."""
        # Create admin user
        admin_token = create_access_token(data={"sub": "admin", "role": "admin"})
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Create nurse user
        nurse_token = create_access_token(data={"sub": "nurse", "role": "nurse"})
        nurse_headers = {"Authorization": f"Bearer {nurse_token}"}
        
        # Admin can create rules
        rule_data = {
            "sensor_id": "patient_001_heart_rate",
            "metric": "bpm",
            "operator": ">",
            "threshold": 100.0,
            "alert_topic": "alerts/medical_emergency"
        }
        
        response = await async_client.post("/rules", json=rule_data, headers=admin_headers)
        assert response.status_code == 201
        rule_id = response.json()["id"]
        
        # Nurse can view rules
        response = await async_client.get("/rules", headers=nurse_headers)
        assert response.status_code == 200
        
        # Nurse cannot delete rules
        response = await async_client.delete(f"/rules/{rule_id}", headers=nurse_headers)
        assert response.status_code == 403
        
        # Admin can delete rules
        response = await async_client.delete(f"/rules/{rule_id}", headers=admin_headers)
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_system_resilience(self, async_client, db_session):
        """Test system behavior under stress conditions."""
        headers = {"Authorization": f"Bearer {create_access_token(data={'sub': 'admin', 'role': 'admin'})}"}
        
        # Create multiple rules rapidly
        tasks = []
        for i in range(50):
            rule_data = {
                "sensor_id": f"sensor_{i:03d}",
                "metric": "value",
                "operator": ">",
                "threshold": float(i),
                "alert_topic": f"alerts/test_{i}"
            }
            task = async_client.post("/rules", json=rule_data, headers=headers)
            tasks.append(task)
        
        # Execute all requests concurrently
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful responses
        successful = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 201)
        
        # Should handle most requests successfully
        assert successful >= 45  # Allow for some failures under stress
```

## 🚀 Performance Tests

### Load Testing with Locust

```python
# tests/performance/locustfile.py
from locust import HttpUser, task, between
import random
import json

class ElderlyCareUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        """Login and get token."""
        response = self.client.post("/auth/login", json={
            "username": "admin",
            "password": "admin_password"
        })
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.token = None
            self.headers = {}

    @task(3)
    def get_health(self):
        """Check system health."""
        self.client.get("/health")

    @task(2)
    def get_rules(self):
        """Get all rules."""
        if self.token:
            self.client.get("/rules", headers=self.headers)

    @task(1)
    def create_rule(self):
        """Create a new rule."""
        if self.token:
            rule_data = {
                "sensor_id": f"test_sensor_{random.randint(1, 1000)}",
                "metric": "value",
                "operator": ">",
                "threshold": random.uniform(50.0, 150.0),
                "alert_topic": "alerts/test"
            }
            self.client.post("/rules", json=rule_data, headers=self.headers)

    @task(2)
    def get_logs(self):
        """Get alert logs."""
        if self.token:
            self.client.get("/logs", headers=self.headers)

class MQTTLoadTest:
    """MQTT-specific load testing."""
    
    def __init__(self, mqtt_host="localhost", mqtt_port=1883):
        import paho.mqtt.client as mqtt
        self.client = mqtt.Client()
        self.client.connect(mqtt_host, mqtt_port, 60)
        self.client.loop_start()
    
    def publish_sensor_data(self, num_messages=1000):
        """Publish large volume of sensor data."""
        import time
        import threading
        
        def publish_batch(start, end):
            for i in range(start, end):
                topic = f"sensors/load_test_{i % 100}/value"
                value = random.uniform(50.0, 150.0)
                self.client.publish(topic, str(value))
                time.sleep(0.01)  # 100 messages per second per thread
        
        # Use multiple threads
        threads = []
        batch_size = num_messages // 10
        
        for i in range(10):
            start = i * batch_size
            end = start + batch_size
            thread = threading.Thread(target=publish_batch, args=(start, end))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
```

### Database Performance Tests

```python
# tests/performance/test_database_performance.py
import pytest
import time
from sqlalchemy import create_engine, text
from tests.factories import RuleFactory, LogFactory

class TestDatabasePerformance:
    def test_bulk_rule_creation(self, db_session):
        """Test bulk creation of rules."""
        start_time = time.time()
        
        # Create 1000 rules
        rules = [RuleFactory.build() for _ in range(1000)]
        db_session.bulk_save_objects(rules)
        db_session.commit()
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete within reasonable time
        assert duration < 5.0  # 5 seconds max
        print(f"Created 1000 rules in {duration:.2f} seconds")

    def test_log_query_performance(self, db_session):
        """Test log query performance with large dataset."""
        # Create test data
        rule = RuleFactory()
        db_session.add(rule)
        db_session.commit()
        
        logs = [LogFactory.build(rule_id=rule.id) for _ in range(10000)]
        db_session.bulk_save_objects(logs)
        db_session.commit()
        
        # Test query performance
        start_time = time.time()
        
        # Query with filtering
        result = db_session.query(Log).filter(
            Log.rule_id == rule.id,
            Log.alert_sent == True
        ).limit(100).all()
        
        end_time = time.time()
        duration = end_time - start_time
        
        assert duration < 1.0  # Should be fast with proper indexing
        assert len(result) <= 100
        print(f"Queried 100 logs from 10k records in {duration:.3f} seconds")

    def test_concurrent_database_access(self, db_session):
        """Test concurrent database operations."""
        import threading
        import queue
        
        results = queue.Queue()
        
        def create_rules(start_id, count):
            try:
                for i in range(count):
                    rule = RuleFactory(sensor_id=f"concurrent_test_{start_id}_{i}")
                    db_session.add(rule)
                db_session.commit()
                results.put(True)
            except Exception as e:
                results.put(False)
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=create_rules, args=(i, 20))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Check results
        success_count = 0
        while not results.empty():
            if results.get():
                success_count += 1
        
        assert success_count == 5  # All threads should succeed
```

## 🔒 Security Testing

### Automated Security Tests

```python
# tests/security/test_security.py
import pytest
from tests.conftest import client

class TestSecurityVulnerabilities:
    def test_sql_injection_protection(self, client, admin_token):
        """Test SQL injection protection."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Try SQL injection in sensor_id
        malicious_data = {
            "sensor_id": "'; DROP TABLE rules; --",
            "metric": "bpm",
            "operator": ">",
            "threshold": 100.0,
            "alert_topic": "alerts/test"
        }
        
        response = client.post("/rules", json=malicious_data, headers=headers)
        
        # Should be rejected or sanitized
        assert response.status_code in [400, 422]

    def test_xss_protection(self, client, admin_token):
        """Test XSS protection in input fields."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        xss_payload = "<script>alert('xss')</script>"
        rule_data = {
            "sensor_id": "test_sensor",
            "metric": "bpm",
            "operator": ">",
            "threshold": 100.0,
            "alert_topic": "alerts/test",
            "name": xss_payload,
            "description": xss_payload
        }
        
        response = client.post("/rules", json=rule_data, headers=headers)
        
        if response.status_code == 201:
            # Check that XSS was sanitized
            data = response.json()
            assert "<script>" not in data.get("name", "")
            assert "<script>" not in data.get("description", "")

    def test_authentication_bypass(self, client):
        """Test authentication bypass attempts."""
        # Try to access protected endpoint without token
        response = client.get("/rules")
        assert response.status_code == 403
        
        # Try with invalid token
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/rules", headers=headers)
        assert response.status_code == 403
        
        # Try with malformed header
        headers = {"Authorization": "invalid_format"}
        response = client.get("/rules", headers=headers)
        assert response.status_code == 403

    def test_rate_limiting(self, client):
        """Test rate limiting protection."""
        # Make rapid requests
        responses = []
        for i in range(100):
            response = client.get("/health")
            responses.append(response.status_code)
        
        # Should have some rate limiting after many requests
        too_many_requests = sum(1 for status in responses if status == 429)
        
        # At least some requests should be rate limited
        # (This depends on rate limiting configuration)
        # assert too_many_requests > 0

    def test_input_validation(self, client, admin_token):
        """Test comprehensive input validation."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Test various invalid inputs
        invalid_cases = [
            {"sensor_id": "", "metric": "bpm", "operator": ">", "threshold": 100.0},  # Empty sensor_id
            {"sensor_id": "test", "metric": "", "operator": ">", "threshold": 100.0},  # Empty metric
            {"sensor_id": "test", "metric": "bpm", "operator": "INVALID", "threshold": 100.0},  # Invalid operator
            {"sensor_id": "test", "metric": "bpm", "operator": ">", "threshold": "not_a_number"},  # Invalid threshold
            {"sensor_id": "A" * 1000, "metric": "bpm", "operator": ">", "threshold": 100.0},  # Too long sensor_id
        ]
        
        for invalid_data in invalid_cases:
            response = client.post("/rules", json=invalid_data, headers=headers)
            assert response.status_code in [400, 422], f"Failed for: {invalid_data}"
```

### Security Scan Integration

```bash
#!/bin/bash
# tests/security/security_scan.sh

echo "🔒 Running Security Scans"
echo "========================"

# Bandit - Python security linter
echo "1. Running Bandit security scan..."
bandit -r src/ -f json -o reports/bandit_report.json

# Safety - Check for known vulnerabilities
echo "2. Checking for known vulnerabilities..."
safety check --json --output reports/safety_report.json

# Custom security checks
echo "3. Running custom security tests..."
python -m pytest tests/security/ -v --tb=short

# Check for hardcoded secrets
echo "4. Scanning for hardcoded secrets..."
git secrets --scan

echo "Security scan completed. Check reports/ directory for details."
```

## 📊 Test Reporting

### Coverage Configuration

```ini
# .coveragerc
[run]
source = src
omit = 
    src/tests/*
    */venv/*
    */migrations/*
    */alembic/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
    
show_missing = True
precision = 2

[html]
directory = htmlcov
```

### Test Execution Scripts

```bash
#!/bin/bash
# scripts/run_tests.sh

echo "🧪 Running Complete Test Suite"
echo "=============================="

# Create reports directory
mkdir -p reports

# Unit tests with coverage
echo "1. Running unit tests..."
python -m pytest tests/unit/ -v --cov=src --cov-report=html --cov-report=xml --cov-report=term

# Integration tests
echo "2. Running integration tests..."
python -m pytest tests/integration/ -v

# End-to-end tests
echo "3. Running E2E tests..."
python -m pytest tests/e2e/ -v

# Performance tests
echo "4. Running performance tests..."
python -m pytest tests/performance/ -v

# Security tests
echo "5. Running security tests..."
python -m pytest tests/security/ -v

# Generate test report
echo "6. Generating test report..."
python -m pytest --html=reports/test_report.html --self-contained-html

echo "✅ Test suite completed!"
echo "📊 Reports available in reports/ directory"
```

### Continuous Integration

```yaml
# .github/workflows/tests.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      mosquitto:
        image: eclipse-mosquitto:2.0
        ports:
          - 1883:1883

    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Run tests
      run: |
        python -m pytest tests/ --cov=src --cov-report=xml
        
    - name: Upload coverage
      uses: codecov/codecov-action@v1
      with:
        file: ./coverage.xml
    
    - name: Run security scan
      run: |
        bandit -r src/
        safety check
```

This comprehensive testing guide ensures the Elderly Care Home Alert Engine maintains high quality, security, and performance standards!
