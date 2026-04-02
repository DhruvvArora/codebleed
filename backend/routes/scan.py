"""
CodeBleed — unified scan wrapper route.

This endpoint keeps the existing component endpoints/services intact,
and adds a thin orchestration layer that returns a frontend-ready payload.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.scan_orchestrator import run_scan_pipeline

logger = logging.getLogger(__name__)
router = APIRouter(prefix="", tags=["Unified Scan"])


class ScanRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL")
    branch: Optional[str] = Field(default=None, description="Branch to scan")
    max_commits: int = Field(default=20, ge=1, le=100)
    max_paths: int = Field(default=5, ge=1, le=20)
    max_risks: int = Field(default=5, ge=1, le=20)

    # Frontend compatibility fields. They are accepted and safely ignored for now.
    scan_mode: Optional[str] = None
    include_commit_history: bool = True
    include_dependencies: bool = True
    include_secrets: bool = True
    include_endpoints: bool = True


@router.post(
    "/scan",
    summary="Run the full repository scan and return a unified UI payload",
    description=(
        "Executes ingestion, security extraction, graph build, threat intelligence, "
        "and AI reasoning in sequence, then adapts the result into one frontend-ready response."
    ),
)
async def scan(request: ScanRequest):
    try:
        return await run_scan_pipeline(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unified scan pipeline failed")
        raise HTTPException(status_code=500, detail=f"Unified scan failed: {exc}")
