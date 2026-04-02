"""
RepoGuard — Dependency file detection and extraction.

Scans the repo tree for known dependency manifests, fetches their
contents, and returns structured DependencyFile objects.
"""

from __future__ import annotations

import logging
from typing import Optional

from github.Repository import Repository as GHRepo

from schemas.repo_ingestion import DependencyFile
from services.repo_ingestion.github_client import GitHubClient
from utils.repo_helpers import is_dependency_file, dependency_file_type

logger = logging.getLogger(__name__)


def find_and_fetch_dependency_files(
    client: GitHubClient,
    repo: GHRepo,
    ref: Optional[str] = None,
) -> list[DependencyFile]:
    """
    Walk the repo tree, identify dependency manifests, fetch their
    contents, and return structured results.
    """
    all_paths = client.get_full_tree_paths(repo, ref=ref)
    dep_paths = [p for p in all_paths if is_dependency_file(p)]

    if not dep_paths:
        logger.info("No dependency files found in repo tree")
        return []

    logger.info("Found %d dependency file(s): %s", len(dep_paths), dep_paths)

    dep_files: list[DependencyFile] = []
    for path in dep_paths:
        content = client.get_file_content(repo, path, ref=ref)
        file_type = dependency_file_type(path) or path
        dep_files.append(
            DependencyFile(
                path=path,
                type=file_type,
                content=content or "",
            )
        )

    return dep_files
