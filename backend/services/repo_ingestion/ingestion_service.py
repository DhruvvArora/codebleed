"""
RepoGuard — Ingestion orchestrator (Component 1 entry point).

This is the single function that routes/API handlers should call.
It wires together: GitHub client → parser → dependency detection
and returns the final IngestionResponse.
"""

from __future__ import annotations

import logging

from schemas.repo_ingestion import IngestionRequest, IngestionResponse
from services.repo_ingestion.github_client import GitHubClient
from services.repo_ingestion.repo_parser import (
    parse_repo_metadata,
    parse_commits,
    build_summary,
)
from services.repo_ingestion.dependency_parser import find_and_fetch_dependency_files

logger = logging.getLogger(__name__)


async def ingest_repo(request: IngestionRequest) -> IngestionResponse:
    """
    Full ingestion pipeline:
      1. Validate + connect to GitHub
      2. Fetch repo metadata
      3. Fetch commit history (with file diffs)
      4. Detect and fetch dependency files
      5. Build summary
      6. Return structured IngestionResponse
    """
    logger.info("Starting ingestion for %s", request.repo_url)

    # 1 — GitHub client (picks up GITHUB_TOKEN from env if set)
    client = GitHubClient()
    repo = client.get_repo(request.repo_url)

    # 2 — Metadata
    raw_meta = client.get_repo_metadata(repo)
    repo_info = parse_repo_metadata(raw_meta)

    # 3 — Commits
    branch = request.branch or repo.default_branch
    raw_commits = client.get_commits(
        repo,
        branch=branch,
        max_commits=request.max_commits,
    )
    commits = parse_commits(raw_commits)

    # 4 — Dependency files
    dep_files = find_and_fetch_dependency_files(client, repo, ref=branch)

    # 5 — Summary
    summary = build_summary(commits, dependency_file_count=len(dep_files))

    logger.info(
        "Ingestion complete — %d commits, %d dep files, %d unique files",
        summary.total_commits,
        summary.dependency_files_found,
        summary.total_unique_files_touched,
    )

    # 6 — Assemble response
    return IngestionResponse(
        repository=repo_info,
        commits=commits,
        dependency_files=dep_files,
        summary=summary,
    )
