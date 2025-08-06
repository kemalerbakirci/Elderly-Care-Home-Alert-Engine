"""
auth_routes.py

Authentication and user management API endpoints.
Provides secure login, logout, user management, and audit logging.
"""

from datetime import timedelta, datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import crud, schemas, models
from .database import get_db
from .security import (
    verify_password, get_password_hash, create_access_token,
    get_current_user, require_admin, require_viewer,
    log_security_event, ACCESS_TOKEN_EXPIRE_MINUTES
)

router = APIRouter()

@router.post("/login", response_model=schemas.Token)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return JWT token.
    """
    # Get client IP
    client_ip = request.client.host
    
    # Find user
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        # Log failed login attempt
        log_security_event(
            event_type="FAILED_LOGIN",
            user_id=user.id if user else None,
            details=f"Failed login attempt for username: {form_data.username} from IP: {client_ip}"
        )
        
        # Create audit log entry
        if user:
            audit_log = models.AuditLog(
                user_id=user.id,
                action="FAILED_LOGIN",
                ip_address=client_ip,
                success=False,
                details=f"Invalid password for user {form_data.username}"
            )
            db.add(audit_log)
            db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    
    # Log successful login
    audit_log = models.AuditLog(
        user_id=user.id,
        action="LOGIN",
        ip_address=client_ip,
        success=True,
        details=f"Successful login for user {user.username}"
    )
    db.add(audit_log)
    db.commit()
    
    log_security_event(
        event_type="SUCCESSFUL_LOGIN",
        user_id=user.id,
        details=f"User {user.username} logged in from IP: {client_ip}"
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": user.role
    }

@router.post("/logout")
async def logout(
    request: Request,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout user (client should discard token).
    """
    client_ip = request.client.host
    
    # Log logout
    audit_log = models.AuditLog(
        user_id=current_user.id,
        action="LOGOUT",
        ip_address=client_ip,
        success=True,
        details=f"User {current_user.username} logged out"
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=schemas.UserOut)
async def get_current_user_info(current_user: models.User = Depends(get_current_user)):
    """
    Get current user information.
    """
    return current_user

@router.post("/users", response_model=schemas.UserOut)
async def create_user(
    user_data: schemas.UserCreate,
    request: Request,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Create a new user (admin only).
    """
    # Check if username or email already exists
    existing_user = db.query(models.User).filter(
        (models.User.username == user_data.username) | 
        (models.User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists"
        )
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    db_user = models.User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        role=user_data.role
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Log user creation
    audit_log = models.AuditLog(
        user_id=current_user.id,
        action="CREATE_USER",
        resource=f"user_{db_user.id}",
        ip_address=request.client.host,
        success=True,
        details=f"Created user {db_user.username} with role {db_user.role}"
    )
    db.add(audit_log)
    db.commit()
    
    return db_user

@router.get("/users", response_model=List[schemas.UserOut])
async def list_users(
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    List all users (admin only).
    """
    return db.query(models.User).all()

@router.put("/users/{user_id}/activate")
async def activate_user(
    user_id: int,
    request: Request,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Activate a user account (admin only).
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.is_active = True
    db.commit()
    
    # Log activation
    audit_log = models.AuditLog(
        user_id=current_user.id,
        action="ACTIVATE_USER",
        resource=f"user_{user_id}",
        ip_address=request.client.host,
        success=True,
        details=f"Activated user {user.username}"
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": f"User {user.username} activated successfully"}

@router.put("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    request: Request,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Deactivate a user account (admin only).
    """
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=400, 
            detail="Cannot deactivate your own account"
        )
    
    user.is_active = False
    db.commit()
    
    # Log deactivation
    audit_log = models.AuditLog(
        user_id=current_user.id,
        action="DEACTIVATE_USER",
        resource=f"user_{user_id}",
        ip_address=request.client.host,
        success=True,
        details=f"Deactivated user {user.username}"
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": f"User {user.username} deactivated successfully"}

@router.get("/audit-logs", response_model=List[schemas.AuditLogOut])
async def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get audit logs (admin only).
    """
    logs = db.query(models.AuditLog).order_by(
        models.AuditLog.timestamp.desc()
    ).offset(offset).limit(limit).all()
    
    return logs
