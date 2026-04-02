"""
RepoGuard — API route for graph threat intelligence (Component 4).
"""

from __future__ import annotations
import logging
from fastapi import APIRouter, HTTPException
from schemas.threat_intelligence import ThreatIntelligenceRequest, ThreatIntelligenceResponse
from services.threat_intelligence.threat_query_service import perform_threat_analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/threat", tags=["Threat Intelligence"])


@router.post(
    "/intelligence",
    response_model=ThreatIntelligenceResponse,
    summary="Compute graph-based threat intelligence for a repository",
    description=(
        "Executes graph-native Cypher queries to find attack paths, "
        "blast radius, root causes, and suggested fixes."
    )
)
async def intelligence(request: ThreatIntelligenceRequest):
    """
    POST /threat/intelligence
    Body: repository_url, and query limit parameters.
    """
    try:
        result = perform_threat_analysis(request)
        return result
    except Exception as exc:
        logger.exception("Graph threat intelligence failed")
        raise HTTPException(
            status_code=500,
            detail=f"Threat intelligence processing failed: {exc}",
        )
