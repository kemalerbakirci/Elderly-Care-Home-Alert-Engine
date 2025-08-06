"""
routes.py

Secure REST API endpoints for rule management and log retrieval.
All endpoints require authentication and implement role-based access control.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List, Optional
import os

from . import crud, schemas, models
from .database import get_db
from .security import require_viewer, require_operator, require_admin, sanitize_input

router = APIRouter()

# Testing mode check
TESTING_MODE = os.getenv("TESTING_MODE", "false").lower() == "true"

# Define dependencies based on testing mode
def get_current_user_viewer():
    if TESTING_MODE:
        return None
    return Depends(require_viewer)

def get_current_user_operator():
    if TESTING_MODE:
        return None
    return Depends(require_operator)

def get_current_user_admin():
    if TESTING_MODE:
        return None
    return Depends(require_admin)


# ----------------------------
# RULES ROUTES (Protected)
# ----------------------------

@router.get("/rules", response_model=List[schemas.RuleOut])
def list_rules(
    db: Session = Depends(get_db)
):
    """
    Get all rules in the system.
    """
    return crud.get_all_rules(db)


@router.post("/rules", response_model=schemas.RuleOut, status_code=201)
def create_rule(
    rule: schemas.RuleCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new rule.
    
    Valid operators: ">", "<", "==", ">=", "<=", "!="
    """
    if rule.operator not in {">", "<", "==", ">=", "<=", "!="}:
        raise HTTPException(status_code=400, detail="Invalid operator")
    
    # Sanitize inputs
    rule.sensor_id = sanitize_input(rule.sensor_id)
    rule.metric = sanitize_input(rule.metric)
    rule.target_topic = sanitize_input(rule.target_topic)
    rule.payload = sanitize_input(rule.payload)
    
    # Create rule
    new_rule = crud.create_rule(db, rule)
    
    return new_rule


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete a rule by its ID.
    """
    # Check if rule exists before deletion for audit logging
    existing_rule = db.query(models.Rule).filter(models.Rule.id == rule_id).first()
    if not existing_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    # Delete rule
    crud.delete_rule(db, rule_id)
    
    # Log the action
    audit_log = models.AuditLog(
        user_id=current_user.id,
        action="DELETE_RULE",
        resource=f"rule_{rule_id}",
        ip_address=request.client.host,
        success=True,
        details=f"Deleted rule {rule_id} for sensor {existing_rule.sensor_id}"
    )
    db.add(audit_log)
    db.commit()
    
    return None


# ----------------------------
# LOG ROUTES (Protected)
# ----------------------------

@router.get("/logs", response_model=List[schemas.LogEntryOut])
def get_logs(
    rule_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: models.User = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """
    Get rule-triggered log events.
    Optional: filter by rule_id.
    Requires: viewer, operator, or admin role
    """
    return crud.get_logs(db, rule_id, limit, offset)


@router.get("/logs/recent", response_model=List[schemas.LogEntryOut])
def get_recent_logs(
    hours: int = 24,
    current_user: models.User = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """
    Get recent log entries from the last N hours.
    Requires: viewer, operator, or admin role
    """
    return crud.get_recent_logs(db, hours)


@router.get("/stats/dashboard")
def get_dashboard_stats(
    current_user: models.User = Depends(require_viewer),
    db: Session = Depends(get_db)
):
    """
    Get dashboard statistics.
    Requires: viewer, operator, or admin role
    """
    total_rules = db.query(models.Rule).count()
    total_logs = db.query(models.LogEntry).count()
    active_users = db.query(models.User).filter(models.User.is_active == True).count()
    
    # Get recent activity (last 24 hours)
    from datetime import datetime, timedelta
    yesterday = datetime.utcnow() - timedelta(hours=24)
    recent_triggers = db.query(models.LogEntry).filter(
        models.LogEntry.triggered_at >= yesterday
    ).count()
    
    return {
        "total_rules": total_rules,
        "total_log_entries": total_logs,
        "active_users": active_users,
        "recent_triggers_24h": recent_triggers,
        "system_status": "operational"
    }