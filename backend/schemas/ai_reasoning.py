"""
RepoGuard — Pydantic models for Component 5: AI Reasoning.

Defines the request for generating AI reports from graph intelligence
and the structured AI report response.
"""

from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, Field
from schemas.threat_intelligence import ThreatIntelligenceResponse


class AIReasoningRequest(BaseModel):
    """
    Accepts the structured output from Component 4 (Threat Intelligence).
    """
    repository: dict
    threat_intelligence: ThreatIntelligenceResponse
    report_style: str = Field(default="analyst", description="analyst, executive, or developer")
    max_recommendations: int = Field(default=4, ge=1, le=10)
    include_developer_summary: bool = Field(default=True)


class AIReport(BaseModel):
    """The structured output derived from AI reasoning."""
    threat_title: str
    severity: str
    executive_summary: str
    why_it_matters: str
    affected_assets: List[str] = []
    key_findings: List[str] = []
    recommended_fixes: List[str] = []
    developer_summary: Optional[str] = None
    confidence_note: str


class AIReasoningResponse(BaseModel):
    """The final AI reasoning response wrapper."""
    repository: dict
    ai_report: AIReport
    summary: dict
    status: str = "ai_reasoning_completed"
