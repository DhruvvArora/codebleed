"""
RepoGuard — Commit Mapper.

Maps findings (by file path) to the most recent commit that touched them.
"""

from __future__ import annotations
from typing import Optional
from schemas.repo_ingestion import IngestionResponse


def get_latest_commit_for_file(
    ingestion_data: IngestionResponse, file_path: str
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (commit_sha, author_name, date) for the given file_path
    by looking at the ingestion commits list (which is assumed reverse-chronological).
    """
    for commit in ingestion_data.commits:
        for f in commit.files:
            if f.path == file_path:
                return commit.sha, commit.author_name, commit.date
    return None, None, None
