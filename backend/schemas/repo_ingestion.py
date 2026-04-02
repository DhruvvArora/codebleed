"""
RepoGuard — Pydantic models for Component 1: Repo Ingestion.

These schemas define the request/response contract for ingestion.
They are intentionally kept *separate* from graph/security schemas
so later components can import and extend as needed.
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


import os

# ── Request Models ─────────────────────────────────────────────────

class IngestionRequest(BaseModel):
    """POST body accepted by /repo/ingest."""
    repo_url: str = Field(
        ...,
        description="GitHub repository URL (e.g. https://github.com/owner/repo)",
        examples=["https://github.com/pallets/flask"],
    )
    branch: Optional[str] = Field(
        default=None,
        description="Branch to analyse. Defaults to the repo's default branch.",
    )
    max_commits: int = Field(
        default=int(os.getenv("DEFAULT_MAX_COMMITS", "20")),
        ge=1,
        le=100,
        description="Maximum number of recent commits to fetch.",
    )


# ── Response sub-models ────────────────────────────────────────────

class RepositoryInfo(BaseModel):
    name: str
    owner: str
    url: str
    default_branch: str


class FileChange(BaseModel):
    path: str
    status: str          # added | modified | removed | renamed
    additions: int = 0
    deletions: int = 0
    changes: int = 0


class CommitInfo(BaseModel):
    sha: str
    message: str
    author_name: str
    author_email: str
    date: str            # ISO-8601
    files: list[FileChange] = []


class DependencyFile(BaseModel):
    path: str
    type: str            # e.g. "package.json", "requirements.txt"
    content: str = ""    # raw file content


class IngestionSummary(BaseModel):
    total_commits: int = 0
    total_unique_files_touched: int = 0
    dependency_files_found: int = 0


# ── Top-level response ─────────────────────────────────────────────

class IngestionResponse(BaseModel):
    """Full structured output of Component 1."""
    repository: RepositoryInfo
    commits: list[CommitInfo] = []
    dependency_files: list[DependencyFile] = []
    summary: IngestionSummary
