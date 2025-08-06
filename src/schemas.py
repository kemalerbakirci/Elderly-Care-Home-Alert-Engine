"""
schemas.py

Pydantic models for API request/response validation and serialization.
These schemas ensure:
- Clients cannot send malformed or insecure data
- API responses are well-structured and documented
- Secure authentication and authorization

FastAPI uses Pydantic under the hood for:
- Type enforcement
- Validation errors
- OpenAPI schema generation
- Data sanitization
"""

from pydantic import BaseModel, Field, EmailStr, field_validator
from datetime import datetime
from typing import Optional, List
import re


# --------------------------------------
# AUTHENTICATION SCHEMAS
# --------------------------------------

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., json_schema_extra={"example": "user@example.com"})
    role: str = Field(..., pattern="^(admin|operator|viewer)$", json_schema_extra={"example": "admin"})

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserOut(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str = Field(..., json_schema_extra={"example": "admin"})
    password: str = Field(..., json_schema_extra={"example": "SecurePass123!"})


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


# --------------------------------------
# SECURITY SCHEMAS
# --------------------------------------

class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    resource: Optional[str]
    ip_address: Optional[str]
    success: bool
    details: Optional[str]
    timestamp: datetime
    
    class Config:
        from_attributes = True


class SecurityEvent(BaseModel):
    event_type: str = Field(..., json_schema_extra={"example": "FAILED_LOGIN"})
    details: str = Field(..., json_schema_extra={"example": "Invalid credentials for user admin"})
    ip_address: Optional[str] = Field(None, json_schema_extra={"example": "192.168.1.100"})
    user_agent: Optional[str] = Field(None, json_schema_extra={"example": "Mozilla/5.0..."})


# --------------------------------------
# RULE SCHEMAS (Enhanced with Security)
# --------------------------------------

class RuleBase(BaseModel):
    sensor_id: str = Field(..., min_length=1, max_length=50, json_schema_extra={"example": "bed_sensor_1"})
    metric: str = Field(..., min_length=1, max_length=50, json_schema_extra={"example": "motion"})
    operator: str = Field(..., pattern="^(==|!=|>|<|>=|<=)$", json_schema_extra={"example": "=="})
    threshold: float = Field(..., json_schema_extra={"example": 0.0})
    target_topic: str = Field(..., min_length=1, max_length=100, json_schema_extra={"example": "alerts/notify"})
    payload: str = Field(..., min_length=1, max_length=500, json_schema_extra={"example": "ALERT_INACTIVITY"})

    @field_validator('sensor_id', 'metric')
    @classmethod
    def validate_alphanumeric_fields(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Field can only contain letters, numbers, underscores, and hyphens')
        return v

    @field_validator('target_topic')
    @classmethod
    def validate_topic(cls, v):
        if not re.match(r'^[a-zA-Z0-9_/-]+$', v):
            raise ValueError('Topic can only contain letters, numbers, underscores, hyphens, and forward slashes')
        return v


class RuleCreate(RuleBase):
    """ Schema for creating a new rule """
    pass


class RuleOut(RuleBase):
    """ Schema for reading a rule (response) """
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --------------------------------------
# LOG ENTRY SCHEMAS
# --------------------------------------

class LogEntryBase(BaseModel):
    rule_id: int
    sensor_id: str
    metric: str
    value: float


class LogEntryOut(LogEntryBase):
    event_id: int
    triggered_at: datetime

    class Config:
        from_attributes = True


# --------------------------------------
# API RESPONSE SCHEMAS
# --------------------------------------

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None


class HealthCheck(BaseModel):
    status: str = "ok"
    timestamp: datetime
    version: str = "1.0.0"
    services: dict = Field(default_factory=dict)