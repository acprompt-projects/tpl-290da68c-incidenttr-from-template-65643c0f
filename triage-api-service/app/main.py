from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    IncidentCreate, IncidentOut, TriageUpdate, ErrorResponse,
    Severity, IncidentStatus,
)

app = FastAPI(title="Incident Triage Service", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory store — replace with DB in production
_incidents: dict[str, dict] = {}


def _classify_severity(payload: IncidentCreate) -> Severity:
    """Stub for classification model integration.
    In production, call the ML model or rules engine here."""
    if payload.severity:
        return payload.severity
    labels = payload.source.labels
    if labels.get("priority") == "p1":
        return Severity.CRITICAL
    if labels.get("priority") == "p2":
        return Severity.HIGH
    if "warn" in payload.title.lower():
        return Severity.MEDIUM
    return Severity.LOW


def _deduplicate(payload: IncidentCreate) -> Optional[str]:
    """Return existing incident id if this alert is a duplicate."""
    if not payload.dedup_key:
        return None
    for inc in _incidents.values():
        if inc["dedup_key"] == payload.dedup_key and inc["status"] != IncidentStatus.RESOLVED:
            return inc["id"]
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_out(data: dict) -> IncidentOut:
    return IncidentOut(**data)


@app.post(
    "/incidents",
    response_model=IncidentOut,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"model": ErrorResponse}},
)
def create_incident(payload: IncidentCreate):
    existing = _deduplicate(payload)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Duplicate incident: existing id={existing}",
        )

    severity = _classify_severity(payload)
    inc_id = str(uuid.uuid4())
    now = _now()
    record = {
        "id": inc_id,
        "title": payload.title,
        "description": payload.description,
        "severity": severity,
        "status": IncidentStatus.OPEN,
        "assignee": None,
        "notes": None,
        "source": payload.source.model_dump(),
        "dedup_key": payload.dedup_key,
        "correlation_id": payload.correlation_id,
        "created_at": now,
        "updated_at": now,
    }
    _incidents[inc_id] = record
    return _to_out(record)


@app.get(
    "/incidents/{incident_id}",
    response_model=IncidentOut,
    responses={404: {"model": ErrorResponse}},
)
def get_incident(incident_id: str):
    record = _incidents.get(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _to_out(record)


@app.patch(
    "/incidents/{incident_id}/triage",
    response_model=IncidentOut,
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def update_triage(incident_id: str, update: TriageUpdate):
    record = _incidents.get(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="Incident not found")

    if record["status"] == IncidentStatus.RESOLVED:
        raise HTTPException(status_code=422, detail="Cannot triage a resolved incident")

    changed = False
    for field in ("severity", "status", "assignee", "notes"):
        val = getattr(update, field)
        if val is not None:
            record[field] = val
            changed = True

    if not changed:
        raise HTTPException(status_code=422, detail="No valid fields supplied for update")

    if record["status"] == IncidentStatus.TRIAGING and not record.get("assignee"):
        record["status"] = IncidentStatus.ACKNOWLEDGED

    record["updated_at"] = _now()
    return _to_out(record)


@app.get("/health")
def health():
    return {"status": "ok", "incidents_total": len(_incidents)}