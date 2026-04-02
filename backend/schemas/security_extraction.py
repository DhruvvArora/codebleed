"""
RepoGuard — Pydantic models for Component 2: Security Extraction.

These schemas define the request (which is Component 1's output) 
and the response (structured security findings).
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field
from schemas.repo_ingestion import RepositoryInfo, IngestionResponse

# ── Response Sub-models ────────────────────────────────────────────

class SecretFinding(BaseModel):
    id: str
    type: str
    value_preview: str
    file_path: Optional[str] = None
    source: str
    commit_sha: Optional[str] = None
    author_name: Optional[str] = None
    date: Optional[str] = None

class DependencyFinding(BaseModel):
    id: str
    name: str
    version: str
    source_file: str
    risk_status: str
    reason: Optional[str] = None

class EndpointFinding(BaseModel):
    id: str
    route: str
    method: str
    file_path: str
    source: str

class RiskyFileFinding(BaseModel):
    id: str
    file_path: str
    risk_type: str
    reason: str

class SecuritySummary(BaseModel):
    secrets_found: int = 0
    dependencies_extracted: int = 0
    dependency_risk_candidates: int = 0
    endpoints_found: int = 0
    risky_files_tagged: int = 0

# ── Top-level Response ─────────────────────────────────────────────

class SecurityExtractionResponse(BaseModel):
    """Full structured output of Component 2."""
    repository: RepositoryInfo
    secrets: list[SecretFinding] = []
    dependencies: list[DependencyFinding] = []
    endpoints: list[EndpointFinding] = []
    risky_files: list[RiskyFileFinding] = []
    summary: SecuritySummary
