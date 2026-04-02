"""
RepoGuard — Pydantic models for Component 4: Threat Intelligence.

Defines the request for querying graph intelligence and the structured
results for attack paths, blast radius, root causes, and fix candidates.
"""

from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, Field


# ── Request Model ──────────────────────────────────────────────────

class ThreatIntelligenceRequest(BaseModel):
    repository_url: str = Field(..., description="The repository URL to analyze.")
    max_paths: int = Field(default=5, ge=1, le=20)
    max_risks: int = Field(default=5, ge=1, le=20)
    include_fix_candidates: bool = Field(default=True)


# ── Response Sub-models ────────────────────────────────────────────

class AttackPath(BaseModel):
    path_id: str
    path_type: str
    entry_node_id: str
    target_node_id: str
    node_ids: List[str] = []
    edge_types: List[str] = []
    summary: str
    severity_hint: str  # critical, high, medium, low


class RiskNode(BaseModel):
    id: str
    label: str
    name: str
    connected_risk_count: int
    reason: str


class TopRisks(BaseModel):
    dependencies: List[RiskNode] = []
    files: List[RiskNode] = []
    endpoints: List[RiskNode] = []


class RootCause(BaseModel):
    commit_sha: str
    developer_name: str
    developer_email: str
    risk_links: int
    reason: str


class FixCandidate(BaseModel):
    fix_id: str
    fix_type: str
    target_node_id: str
    title: str
    description: str
    estimated_paths_reduced: int
    priority: int


class IntelligenceSummary(BaseModel):
    attack_paths_found: int = 0
    top_dependency_risks: int = 0
    top_file_risks: int = 0
    top_endpoint_risks: int = 0
    root_causes_found: int = 0
    fix_candidates_found: int = 0


# ── Top-level Response ─────────────────────────────────────────────

class ThreatIntelligenceResponse(BaseModel):
    repository: dict
    attack_paths: List[AttackPath] = []
    top_risks: TopRisks
    root_causes: List[RootCause] = []
    fix_candidates: List[FixCandidate] = []
    summary: IntelligenceSummary
