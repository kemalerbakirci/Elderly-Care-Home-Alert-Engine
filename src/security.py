"""
security.py

Authentication and authorization utilities for the Elderly Care Home Alert Engine.
Implements JWT token-based authentication with role-based access control.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from . import models
from .database import get_db

load_dotenv()

# Security Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Token handling
security = HTTPBearer()

# User roles for RBAC
class UserRole:
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

class SecurityException(HTTPException):
    """Custom security exception"""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify JWT token and extract user information"""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        
        if username is None:
            raise SecurityException("Invalid authentication credentials")
            
        return {"username": username, "role": role}
    except JWTError:
        raise SecurityException("Invalid authentication credentials")

def get_current_user(
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get current authenticated user"""
    user = db.query(models.User).filter(models.User.username == token_data["username"]).first()
    if user is None:
        raise SecurityException("User not found")
    return user

def require_role(required_roles: List[str]):
    """Dependency to require specific roles"""
    def role_checker(current_user: models.User = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker

# Common role dependencies
require_admin = require_role([UserRole.ADMIN])
require_operator = require_role([UserRole.ADMIN, UserRole.OPERATOR])
require_viewer = require_role([UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER])

def validate_api_key(api_key: str) -> bool:
    """Validate API key for MQTT and external integrations"""
    valid_api_keys = os.getenv("API_KEYS", "").split(",")
    return api_key in valid_api_keys

def rate_limit_check(user_id: int, action: str) -> bool:
    """Simple rate limiting check (can be enhanced with Redis)"""
    # Implement rate limiting logic here
    # For now, return True (allow all)
    return True

def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not input_str:
        return ""
    
    # Remove potentially dangerous characters and SQL injection patterns
    dangerous_chars = ["<", ">", "&", "\"", "'", "/", "\\", ";", "(", ")", "{", "}", "[", "]"]
    sanitized = input_str
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, "")
    
    # Remove SQL comment patterns
    sanitized = sanitized.replace("--", "")
    sanitized = sanitized.replace("/*", "")
    sanitized = sanitized.replace("*/", "")
    
    # Remove common SQL keywords that shouldn't be in normal input
    sql_keywords = ["DROP", "DELETE", "UPDATE", "INSERT", "SELECT", "UNION", "SCRIPT", "EXEC"]
    for keyword in sql_keywords:
        sanitized = sanitized.replace(keyword.upper(), "")
        sanitized = sanitized.replace(keyword.lower(), "")
        sanitized = sanitized.replace(keyword.capitalize(), "")
    
    return sanitized.strip()

def validate_sensor_id(sensor_id: str) -> bool:
    """Validate sensor ID format"""
    import re
    # Only allow alphanumeric, underscore, and dash
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, sensor_id)) and len(sensor_id) <= 50

def log_security_event(event_type: str, user_id: Optional[int], details: str):
    """Log security events for auditing"""
    # This could be enhanced to write to a dedicated security log
    print(f"SECURITY EVENT: {event_type} | User: {user_id} | Details: {details}")
