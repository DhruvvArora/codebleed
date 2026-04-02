"""
RepoGuard — Local repo parser (STRETCH / optional).

Minimal implementation that reads a local git repo using GitPython
and produces the same structured output as the GitHub path.
Only use if GitPython is installed and the user passes a local path.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from schemas.repo_ingestion import (
    CommitInfo,
    DependencyFile,
    FileChange,
    IngestionResponse,
    IngestionSummary,
    RepositoryInfo,
)
from utils.repo_helpers import is_dependency_file, dependency_file_type

logger = logging.getLogger(__name__)


def ingest_local_repo(
    local_path: str,
    branch: Optional[str] = None,
    max_commits: int = 20,
) -> IngestionResponse:
    """
    Parse a local git repo and return structured ingestion data.
    Requires GitPython (pip install gitpython).
    """
    try:
        from git import Repo  # type: ignore
    except ImportError:
        raise RuntimeError(
            "GitPython is required for local repo parsing. "
            "Install with: pip install gitpython"
        )

    if not os.path.isdir(local_path):
        raise ValueError(f"Path does not exist: {local_path}")

    repo = Repo(local_path)
    if repo.bare:
        raise ValueError(f"Repository at {local_path} is bare")

    # ── Metadata ───────────────────────────────────────────────────
    repo_name = os.path.basename(os.path.abspath(local_path))
    active_branch = branch or str(repo.active_branch)
    remotes = list(repo.remotes)
    origin_url = remotes[0].url if remotes else f"local://{local_path}"

    repo_info = RepositoryInfo(
        name=repo_name,
        owner="local",
        url=origin_url,
        default_branch=active_branch,
    )

    # ── Commits ────────────────────────────────────────────────────
    commits: list[CommitInfo] = []
    for git_commit in list(repo.iter_commits(active_branch, max_count=max_commits)):
        files: list[FileChange] = []
        # diff against parent (if any)
        if git_commit.parents:
            diffs = git_commit.parents[0].diff(git_commit, create_patch=False)
            for d in diffs:
                path = d.b_path or d.a_path or ""
                status = "modified"
                if d.new_file:
                    status = "added"
                elif d.deleted_file:
                    status = "removed"
                elif d.renamed_file:
                    status = "renamed"
                files.append(
                    FileChange(path=path, status=status)
                )

        commits.append(
            CommitInfo(
                sha=str(git_commit.hexsha),
                message=git_commit.message.strip(),
                author_name=git_commit.author.name or "unknown",
                author_email=git_commit.author.email or "unknown",
                date=git_commit.committed_datetime.isoformat(),
                files=files,
            )
        )

    # ── Dependency files ───────────────────────────────────────────
    dep_files: list[DependencyFile] = []
    for root, _dirs, filenames in os.walk(local_path):
        # skip .git and node_modules
        rel_root = os.path.relpath(root, local_path)
        if ".git" in rel_root.split(os.sep) or "node_modules" in rel_root.split(os.sep):
            continue
        for fname in filenames:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, local_path)
            if is_dependency_file(rel):
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except Exception:
                    content = ""
                dep_files.append(
                    DependencyFile(
                        path=rel,
                        type=dependency_file_type(rel) or rel,
                        content=content,
                    )
                )

    # ── Summary ────────────────────────────────────────────────────
    files_touched: set[str] = set()
    for c in commits:
        for f in c.files:
            files_touched.add(f.path)

    summary = IngestionSummary(
        total_commits=len(commits),
        total_unique_files_touched=len(files_touched),
        dependency_files_found=len(dep_files),
    )

    return IngestionResponse(
        repository=repo_info,
        commits=commits,
        dependency_files=dep_files,
        summary=summary,
    )
