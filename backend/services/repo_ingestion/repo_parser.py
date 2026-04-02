"""
RepoGuard — Repo parser for ingestion.

Converts raw GitHub API dicts into structured Pydantic models.
Builds the summary statistics that Component 2/3 will later consume.
"""

from __future__ import annotations

from typing import Any

from schemas.repo_ingestion import (
    CommitInfo,
    FileChange,
    IngestionSummary,
    RepositoryInfo,
)


def parse_repo_metadata(raw: dict[str, Any]) -> RepositoryInfo:
    """Map a raw metadata dict to a RepositoryInfo model."""
    return RepositoryInfo(**raw)


def parse_commits(raw_commits: list[dict[str, Any]]) -> list[CommitInfo]:
    """Convert raw commit dicts into CommitInfo models."""
    commits: list[CommitInfo] = []
    for c in raw_commits:
        files = [FileChange(**f) for f in c.get("files", [])]
        commits.append(
            CommitInfo(
                sha=c["sha"],
                message=c["message"],
                author_name=c["author_name"],
                author_email=c["author_email"],
                date=c["date"],
                files=files,
            )
        )
    return commits


def build_summary(
    commits: list[CommitInfo],
    dependency_file_count: int,
) -> IngestionSummary:
    """
    Compute summary stats from parsed commits.
    Counts unique files touched across all commits.
    """
    files_touched: set[str] = set()

    for commit in commits:
        for f in commit.files:
            files_touched.add(f.path)

    return IngestionSummary(
        total_commits=len(commits),
        total_unique_files_touched=len(files_touched),
        dependency_files_found=dependency_file_count,
    )
