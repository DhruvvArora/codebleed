"""
CodeBleed — GitHub API client for repo ingestion.

Handles all external GitHub API calls. Uses PyGithub for the
authenticated/rich API. Only public repositories are supported.
Set GITHUB_TOKEN to avoid tight rate limits on the unauthenticated tier.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from github import Github, GithubException, Auth
from github.Repository import Repository as GHRepo

from utils.repo_helpers import parse_github_url

logger = logging.getLogger(__name__)


class GitHubClient:
    """Thin wrapper around the GitHub API for repo ingestion."""

    def __init__(self, token: Optional[str] = None):
        token = token or os.getenv("GITHUB_TOKEN")
        base_url = os.getenv("GITHUB_API_BASE_URL", "https://api.github.com")

        if token:
            self._gh = Github(auth=Auth.Token(token), base_url=base_url)
            logger.info("GitHub client initialised with token auth.")
        else:
            self._gh = Github(base_url=base_url)
            logger.warning("GitHub client running WITHOUT token — rate limits will be tight.")

    # ── Repository metadata ────────────────────────────────────────

    def get_repo(self, repo_url: str) -> GHRepo:
        """Resolve a GitHub URL to a PyGithub Repository object."""
        owner, name = parse_github_url(repo_url)
        try:
            repo = self._gh.get_repo(f"{owner}/{name}")
            return repo
        except GithubException as exc:
            if exc.status == 404:
                raise ValueError(
                    f"Repository '{owner}/{name}' not found or is private. "
                    "CodeBleed currently supports public repositories only."
                ) from exc
            raise

    def get_repo_metadata(self, repo: GHRepo) -> dict[str, Any]:
        """Return a flat dict of repo-level metadata."""
        return {
            "name": repo.name,
            "owner": repo.owner.login,
            "url": repo.html_url,
            "default_branch": repo.default_branch,
        }

    # ── Commits ────────────────────────────────────────────────────

    def get_commits(
        self,
        repo: GHRepo,
        branch: Optional[str] = None,
        max_commits: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Fetch recent commits (with per-commit file changes).
        Returns a list of raw dicts ready for the parser.
        """
        sha = branch or repo.default_branch
        commits_raw: list[dict[str, Any]] = []

        for commit in repo.get_commits(sha=sha)[:max_commits]:
            files = []
            for f in commit.files:
                files.append(
                    {
                        "path": f.filename,
                        "status": f.status,
                        "additions": f.additions,
                        "deletions": f.deletions,
                        "changes": f.changes,
                    }
                )

            author = commit.commit.author
            commits_raw.append(
                {
                    "sha": commit.sha,
                    "message": commit.commit.message,
                    "author_name": author.name if author else "unknown",
                    "author_email": author.email if author else "unknown",
                    "date": (
                        author.date.isoformat() if author and author.date else ""
                    ),
                    "files": files,
                }
            )

        return commits_raw

    # ── File contents ──────────────────────────────────────────────

    def get_file_content(
        self,
        repo: GHRepo,
        file_path: str,
        ref: Optional[str] = None,
    ) -> Optional[str]:
        """Fetch decoded text content of a single file from the repo."""
        try:
            ref = ref or repo.default_branch
            content_file = repo.get_contents(file_path, ref=ref)
            if isinstance(content_file, list):
                return None
            return content_file.decoded_content.decode("utf-8", errors="replace")
        except GithubException:
            return None

    # ── Tree listing ───────────────────────────────────────────────

    def get_root_tree_paths(
        self, repo: GHRepo, ref: Optional[str] = None
    ) -> list[str]:
        """Return file paths at the repo root level."""
        ref = ref or repo.default_branch
        try:
            tree = repo.get_git_tree(ref, recursive=False)
            return [item.path for item in tree.tree]
        except GithubException:
            return []

    def get_full_tree_paths(
        self, repo: GHRepo, ref: Optional[str] = None
    ) -> list[str]:
        """Return all file paths in the repo (recursive)."""
        ref = ref or repo.default_branch
        try:
            tree = repo.get_git_tree(ref, recursive=True)
            return [item.path for item in tree.tree]
        except GithubException:
            return []
