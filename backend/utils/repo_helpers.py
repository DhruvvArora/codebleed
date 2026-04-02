"""
RepoGuard — Utility helpers for repo ingestion.
Small, reusable functions that stay independent of business logic.
"""

import re
from typing import Optional, Tuple

# ── GitHub URL parsing ─────────────────────────────────────────────

_GITHUB_PATTERN = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/\s#?]+)"
)

def parse_github_url(url: str) -> Tuple[str, str]:
    """
    Extract (owner, repo_name) from a GitHub URL.
    Raises ValueError on invalid URLs.
    """
    match = _GITHUB_PATTERN.match(url.strip().rstrip("/"))
    if not match:
        raise ValueError(f"Invalid GitHub repository URL: {url}")
    owner = match.group("owner")
    repo = match.group("repo").removesuffix(".git")
    return owner, repo


# ── Dependency file detection ──────────────────────────────────────

SUPPORTED_DEPENDENCY_FILES: list[str] = [
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "Cargo.toml",
]

def is_dependency_file(file_path: str) -> bool:
    """Return True if the file basename is a known dependency manifest."""
    basename = file_path.rsplit("/", maxsplit=1)[-1]
    return basename in SUPPORTED_DEPENDENCY_FILES


def dependency_file_type(file_path: str) -> Optional[str]:
    """Return the canonical type name for a dependency file, or None."""
    basename = file_path.rsplit("/", maxsplit=1)[-1]
    return basename if basename in SUPPORTED_DEPENDENCY_FILES else None


# ── Misc helpers ───────────────────────────────────────────────────

def normalize_file_path(path: str) -> str:
    """Strip leading slashes and normalise path separators."""
    return path.lstrip("/").replace("\\", "/")
