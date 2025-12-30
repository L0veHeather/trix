"""Scan API Routes.

REST API endpoints for managing security scans.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from trix.storage import get_database, ScanStatus
from trix.server.app import get_scan_engine
from trix.engine import ScanConfig

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Request/Response Models ====================

class CreateScanRequest(BaseModel):
    """Request model for creating a scan."""
    
    target: str = Field(..., description="Target URL to scan")
    name: str | None = Field(None, description="Optional scan name")
    phases: list[str] | None = Field(None, description="Specific phases to run")
    plugins: list[str] | None = Field(None, description="Specific plugins to use")
    options: dict[str, Any] = Field(default_factory=dict, description="Additional options")


class ScanResponse(BaseModel):
    """Response model for scan data."""
    
    id: str
    name: str | None
    target: str
    status: str
    current_phase: str | None
    progress: float
    started_at: str | None
    completed_at: str | None
    vulnerability_count: int = 0


class ScanListResponse(BaseModel):
    """Response model for scan list."""
    
    scans: list[ScanResponse]
    total: int


# ==================== Endpoints ====================

@router.post("", response_model=ScanResponse)
async def create_scan(request: CreateScanRequest, background_tasks: BackgroundTasks):
    """Create and start a new security scan."""
    db = get_database()
    engine = get_scan_engine()
    
    # Create scan record
    scan = db.create_scan(
        target=request.target,
        name=request.name,
        config={
            "phases": request.phases,
            "plugins": request.plugins,
            "options": request.options,
        },
    )
    
    # Build scan config
    from trix.engine.scan_engine import ScanPhase
    
    # Convert phase strings to ScanPhase enums if provided
    phases_list = None
    if request.phases:
        try:
            phases_list = [ScanPhase(p) for p in request.phases]
        except ValueError:
            pass  # Use default phases if conversion fails
    
    # Build scan config kwargs
    config_kwargs = {
        "target": request.target,
        "name": request.name,
        "scan_id": scan.id,  # Pass database scan_id to engine
        "plugins": request.plugins or [],
    }
    
    # Only add phases if provided and valid
    if phases_list:
        config_kwargs["phases"] = phases_list
    
    config = ScanConfig(**config_kwargs)
    
    # Start scan in background
    background_tasks.add_task(engine.start_scan, config)
    
    logger.info(f"Created scan {scan.id} for target {request.target}")
    
    return ScanResponse(
        id=scan.id,
        name=scan.name,
        target=scan.target,
        status=scan.status.value,
        current_phase=scan.current_phase,
        progress=scan.progress,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        vulnerability_count=0,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    """List all scans with optional filtering."""
    db = get_database()
    
    scan_status = ScanStatus(status) if status else None
    scans = db.list_scans(status=scan_status, limit=limit, offset=offset)
    
    # Get vulnerability counts separately to avoid lazy loading issues
    vuln_counts = {}
    for s in scans:
        vuln_counts[s.id] = db.get_vulnerability_count(s.id)
    
    return ScanListResponse(
        scans=[
            ScanResponse(
                id=s.id,
                name=s.name,
                target=s.target,
                status=s.status.value if s.status else "unknown",
                current_phase=s.current_phase,
                progress=s.progress or 0,
                started_at=s.started_at.isoformat() if s.started_at else None,
                completed_at=s.completed_at.isoformat() if s.completed_at else None,
                vulnerability_count=vuln_counts.get(s.id, 0),
            )
            for s in scans
        ],
        total=len(scans),
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    """Get details of a specific scan."""
    db = get_database()
    scan = db.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get vulnerability count separately to avoid lazy loading
    vuln_count = db.get_vulnerability_count(scan_id)
    
    return ScanResponse(
        id=scan.id,
        name=scan.name,
        target=scan.target,
        status=scan.status.value if scan.status else "unknown",
        current_phase=scan.current_phase,
        progress=scan.progress or 0,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        vulnerability_count=vuln_count,
    )


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get real-time status of a scan.
    
    Returns queue length, completed tasks, and active tasks for state recovery.
    """
    db = get_database()
    engine = get_scan_engine()
    
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get phase results
    phase_results = db.get_phase_results(scan_id)
    
    # Get vulnerability stats
    vuln_stats = db.get_vulnerability_stats(scan_id)
    
    # 🔥 Get dynamic queue info (for state recovery)
    queue_info = {
        "queue_size": 0,
        "active_tasks": [],
        "tasks_completed": 0,
        "tasks_added": 0,
    }
    
    if scan_id in engine._task_queues:
        queue = engine._task_queues[scan_id]
        queue_stats = queue.get_stats()
        queue_info = {
            "queue_size": queue_stats.get("queue_size", 0),
            "tasks_completed": queue_stats.get("tasks_completed", 0),
            "tasks_added": queue_stats.get("tasks_added", 0),
            "tasks_rejected_depth": queue_stats.get("tasks_rejected_depth", 0),
        }
    
    if scan_id in engine._active_task_ids:
        queue_info["active_tasks"] = list(engine._active_task_ids[scan_id])
    
    return {
        "scan_id": scan_id,
        "status": scan.status.value if scan.status else "unknown",
        "current_phase": scan.current_phase,
        "progress": scan.progress or 0,
        "phases": phase_results,
        "vulnerabilities": vuln_stats,
        "is_active": scan_id in engine._tasks,
        # 🔥 New: Queue info for fine-grained tracking
        "queue": queue_info,
    }


@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: str):
    """Pause a running scan."""
    engine = get_scan_engine()
    
    success = await engine.pause_scan(scan_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot pause scan")
    
    return {"status": "paused", "scan_id": scan_id}


@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: str):
    """Resume a paused scan."""
    engine = get_scan_engine()
    
    success = await engine.resume_scan(scan_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot resume scan")
    
    return {"status": "resumed", "scan_id": scan_id}


@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str):
    """Stop a running scan."""
    engine = get_scan_engine()
    
    success = await engine.stop_scan(scan_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot stop scan")
    
    return {"status": "stopped", "scan_id": scan_id}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and all its data."""
    db = get_database()
    engine = get_scan_engine()
    
    # Stop if running
    if scan_id in engine._tasks:
        await engine.stop_scan(scan_id)
    
    # Delete from database
    success = db.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {"status": "deleted", "scan_id": scan_id}
