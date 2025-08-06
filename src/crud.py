"""
crud.py

This module provides safe, reusable database operations:
- Rule creation, listing, deletion
- Logging triggered events
- Filtering logs by rule
"""

from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from fastapi import HTTPException

from . import models, schemas


# --------------------------------------
# RULE OPERATIONS
# --------------------------------------

def get_all_rules(db: Session):
    """
    Fetch all rules from the database.
    """
    return db.query(models.Rule).all()



def get_matching_rules(db: Session, sensor_id: str, metric: str):
    """
    Get all rules that match the given sensor_id and metric.
    """
    return db.query(models.Rule).filter(
        models.Rule.sensor_id == sensor_id,
        models.Rule.metric == metric
    ).all()

def create_rule(db: Session, rule: schemas.RuleCreate):
    """
    Insert a new rule into the database.
    """
    db_rule = models.Rule(**rule.model_dump())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


def delete_rule(db: Session, rule_id: int):
    """
    Delete a rule by ID. Raise 404 if not found.
    """
    rule = db.query(models.Rule).filter(models.Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": f"Rule {rule_id} deleted successfully"}


# --------------------------------------
# LOG OPERATIONS
# --------------------------------------

def log_event(
    db: Session,
    rule_id: int,
    sensor_id: str,
    metric: str,
    value: float
):
    """
    Record an event in the log table when a rule triggers.
    """
    entry = models.LogEntry(
        rule_id=rule_id,
        sensor_id=sensor_id,
        metric=metric,
        value=value
    )
    db.add(entry)
    db.commit()


def get_logs(db: Session, rule_id: int = None):
    """
    Get all log entries, or filter by rule_id if provided.
    """
    query = db.query(models.LogEntry)
    if rule_id:
        query = query.filter(models.LogEntry.rule_id == rule_id)
    return query.order_by(models.LogEntry.triggered_at.desc()).all()