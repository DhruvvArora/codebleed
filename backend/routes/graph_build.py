"""
RepoGuard — API route for graph building (Component 3).
"""

from __future__ import annotations
import logging
from fastapi import APIRouter, HTTPException
from schemas.graph_build import GraphBuildRequest, GraphBuildResponse
from services.graph_build.graph_build_service import build_graph

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/graph", tags=["Graph Builder"])


@router.post(
    "/build",
    response_model=GraphBuildResponse,
    summary="Construct a Neo4j Graph from raw ingestion + security extraction records",
    description=(
        "Accepts Component 1 and Component 2 models and merges "
        "them as structured entities and relationships within Neo4j."
    )
)
async def build(request: GraphBuildRequest):
    """
    POST /graph/build
    Body: JSON with `ingestion_data` and `security_data`.
    """
    try:
        result = build_graph(request)
        return result
    except Exception as exc:
        logger.exception("Graph build failed")
        raise HTTPException(
            status_code=500,
            detail=f"Graph build failed: {exc}",
        )
