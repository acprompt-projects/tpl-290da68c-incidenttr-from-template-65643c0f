from __future__ import annotations
import enum
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AlertSource(BaseModel):
    service: str
    rule_id: str
    labels: dict[str, str] = Field(default_factory=dict)


class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    severity: Optional[Severity] = None
    source: AlertSource
    dedup_key: Optional[str] = None
    correlation_id: Optional[str] = None


class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None


class IncidentOut(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    assignee: Optional[str] = None
    notes: Optional[str] = None
    source: AlertSource
    dedup_key: Optional[str] = None
    correlation_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""