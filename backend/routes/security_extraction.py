"""
RepoGuard — API route for security extraction (Component 2).
"""

from __future__ import annotations
import logging
from fastapi import APIRouter, HTTPException
from schemas.repo_ingestion import IngestionResponse
from schemas.security_extraction import SecurityExtractionResponse
from services.security_extraction.extraction_service import extract_security_findings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/security", tags=["Security Extraction"])


@router.post(
    "/extract",
    response_model=SecurityExtractionResponse,
    summary="Extract security findings from raw ingestion data",
    description=(
        "Accepts raw repository JSON from Component 1 and extracts "
        "secrets, dependencies, endpoints, and risky files."
    )
)
async def extract(request: IngestionResponse):
    """
    POST /security/extract
    Body: JSON from Component 1 (IngestionResponse)
    """
    try:
        result = extract_security_findings(request)
        return result
    except Exception as exc:
        logger.exception("Security extraction failed")
        raise HTTPException(
            status_code=500,
            detail=f"Security extraction failed: {exc}",
        )
