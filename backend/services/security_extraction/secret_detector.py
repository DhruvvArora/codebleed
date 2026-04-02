"""
RepoGuard — Secret Detector.

Scans content (e.g. dependency files, commit messages) for hardcoded secrets
using regex patterns.
"""

from __future__ import annotations
import uuid
from schemas.repo_ingestion import IngestionResponse
from schemas.security_extraction import SecretFinding
from utils.security_patterns import SECRET_PATTERNS
from services.security_extraction.commit_mapper import get_latest_commit_for_file


def _mask_secret(secret_val: str) -> str:
    """Preview only the first 4 chars of the secret."""
    if len(secret_val) > 4:
        return f"{secret_val[:4]}****"
    return "****"


def detect_secrets(ingestion_data: IngestionResponse) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    
    # Check dependency file contents
    for df in ingestion_data.dependency_files:
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(df.content):
                # groups usually contain the actual secret depending on regex
                secret_val = match.group(1) if match.groups() else match.group()
                if not secret_val:
                    continue
                
                c_sha, c_author, c_date = get_latest_commit_for_file(ingestion_data, df.path)
                
                findings.append(
                    SecretFinding(
                        id=f"secret_{uuid.uuid4().hex[:8]}",
                        type=secret_type,
                        value_preview=_mask_secret(secret_val),
                        file_path=df.path,
                        source="dependency_file_content",
                        commit_sha=c_sha,
                        author_name=c_author,
                        date=c_date
                    )
                )
                
    # We could also scan commit messages for leaked secrets
    for commit in ingestion_data.commits:
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(commit.message):
                secret_val = match.group(1) if match.groups() else match.group()
                if not secret_val:
                    continue
                findings.append(
                    SecretFinding(
                        id=f"secret_{uuid.uuid4().hex[:8]}",
                        type=secret_type,
                        value_preview=_mask_secret(secret_val),
                        file_path=None,
                        source="commit_message",
                        commit_sha=commit.sha,
                        author_name=commit.author_name,
                        date=commit.date
                    )
                )
                
    return findings
