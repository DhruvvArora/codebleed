"""
RepoGuard — Thin API route for repo ingestion.
No heavy logic here — just validate → call service → return.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from schemas.repo_ingestion import IngestionRequest, IngestionResponse
from services.repo_ingestion.ingestion_service import ingest_repo

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/repo", tags=["Repo Ingestion"])


@router.post(
    "/ingest",
    response_model=IngestionResponse,
    summary="Ingest a GitHub repository",
    description=(
        "Accepts a GitHub repo URL, fetches metadata, recent commits, "
        "changed files, and dependency manifests. Returns structured "
        "raw repo data for downstream security analysis."
    ),
)
async def ingest(request: IngestionRequest):
    """
    POST /repo/ingest
    Body: { "repo_url": "...", "branch": "main", "max_commits": 20 }
    """
    try:
        result = await ingest_repo(request)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Ingestion failed")
        raise HTTPException(
            status_code=500,
            detail=f"Ingestion failed: {exc}",
        )
