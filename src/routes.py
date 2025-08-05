"""
routes.py

Exposes REST API endpoints for rule management and log retrieval.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from . import crud, schemas
from .database import get_db

router = APIRouter()


# ----------------------------
# RULES ROUTES
# ----------------------------

@router.get("/rules", response_model=List[schemas.RuleOut])
def list_rules(db: Session = Depends(get_db)):
    """
    Get all rules in the system.
    """
    return crud.get_all_rules(db)


@router.post("/rules", response_model=schemas.RuleOut, status_code=201)
def create_rule(rule: schemas.RuleCreate, db: Session = Depends(get_db)):
    """
    Create a new rule.

    Valid operators: ">", "<", "==", ">=", "<=", "!="
    """
    if rule.operator not in {">", "<", "==", ">=", "<=", "!="}:
        raise HTTPException(status_code=400, detail="Invalid operator")
    return crud.create_rule(db, rule)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """
    Delete a rule by its ID.
    """
    crud.delete_rule(db, rule_id)
    return None


# ----------------------------
# LOG ROUTES
# ----------------------------

@router.get("/logs", response_model=List[schemas.LogEntryOut])
def get_logs(rule_id: Optional[int] = None, db: Session = Depends(get_db)):
    """
    Get rule-triggered log events.
    Optional: filter by rule_id.
    """
    return crud.get_logs(db, rule_id)