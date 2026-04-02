"""
RepoGuard — API route for AI reasoning (Component 5).
"""

from __future__ import annotations
import logging
from fastapi import APIRouter, HTTPException
from schemas.ai_reasoning import AIReasoningRequest, AIReasoningResponse
from services.ai_reasoning.ai_reasoning_service import perform_ai_reasoning

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ai", tags=["AI Reasoning"])


@router.post(
    "/reason",
    response_model=AIReasoningResponse,
    summary="Generate human-readable cybersecurity intelligence via AI reasoning",
    description=(
        "Takes structured graph intelligence and uses RocketRide AI "
        "to narrate threats and prioritize remediation steps."
    )
)
async def reason(request: AIReasoningRequest):
    """
    POST /ai/reason
    Body: repository, and full threat_intelligence output from Component 4.
    """
    try:
        result = perform_ai_reasoning(request)
        return result
    except Exception as exc:
        logger.exception("AI reasoning process failed")
        raise HTTPException(
            status_code=500,
            detail=f"AI reasoning process failed: {exc}",
        )
