"""
schemas.py

Pydantic models for API request/response validation and serialization.
These schemas ensure:
- Clients cannot send malformed or insecure data
- API responses are well-structured and documented

FastAPI uses Pydantic under the hood for:
- Type enforcement
- Validation errors
- OpenAPI schema generation
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


# --------------------------------------
# RULE SCHEMAS
# --------------------------------------

class RuleBase(BaseModel):
    sensor_id: str = Field(..., example="bed_sensor_1")
    metric: str = Field(..., example="motion")
    operator: str = Field(..., example="==", pattern="^(==|!=|>|<|>=|<=)$")
    threshold: float = Field(..., example=0.0)
    target_topic: str = Field(..., example="alerts/notify")
    payload: str = Field(..., example="ALERT_INACTIVITY")


class RuleCreate(RuleBase):
    """ Schema for creating a new rule """
    pass


class RuleOut(RuleBase):
    """ Schema for reading a rule (response) """
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


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
        orm_mode = True