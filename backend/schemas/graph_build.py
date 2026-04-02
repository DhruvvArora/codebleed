"""
RepoGuard — Pydantic models for Component 3: Graph Build.

Defines the combined request payload and the graph build summary response.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from schemas.repo_ingestion import IngestionResponse, RepositoryInfo
from schemas.security_extraction import SecurityExtractionResponse


class GraphBuildRequest(BaseModel):
    """
    Accepts the outputs from Component 1 (ingestion_data)
    and Component 2 (security_data).
    """
    ingestion_data: IngestionResponse
    security_data: SecurityExtractionResponse


class NodeSummary(BaseModel):
    Repository: int = 0
    Developer: int = 0
    Commit: int = 0
    File: int = 0
    Dependency: int = 0
    VulnerabilityCandidate: int = 0
    Secret: int = 0
    Endpoint: int = 0
    RiskyFileTag: int = 0


class EdgeSummary(BaseModel):
    PUSHED: int = 0
    IN_REPO: int = 0
    MODIFIED: int = 0
    BELONGS_TO: int = 0
    IMPORTS: int = 0
    HAS_RISK: int = 0
    CONTAINS_SECRET: int = 0
    EXPOSES: int = 0
    TAGGED_AS: int = 0
    INTRODUCES_SECRET: int = 0
    INTRODUCES_ENDPOINT: int = 0
    INTRODUCES_DEP_RISK: int = 0


class GraphSummaryDict(BaseModel):
    nodes_created_or_merged: NodeSummary
    relationships_created_or_merged: EdgeSummary


class GraphBuildResponse(BaseModel):
    """Structured graph build summary returned to the client."""
    repository: RepositoryInfo
    graph_summary: GraphSummaryDict
    status: str = "graph_built"
