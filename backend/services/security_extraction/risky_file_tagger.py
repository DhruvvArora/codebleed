"""
RepoGuard — Risky File Tagger.

Uses filepath heuristics to identify configuration, admin, 
auth, payment, and other sensitive files.
"""

from __future__ import annotations
import uuid
from schemas.repo_ingestion import IngestionResponse
from schemas.security_extraction import RiskyFileFinding
from utils.security_patterns import RISKY_FILE_KEYWORDS


def tag_risky_files(ingestion_data: IngestionResponse) -> list[RiskyFileFinding]:
    """
    Look through all unique files touched across commits and dependency files
    to see if any match our risky heuristics.
    """
    files_to_check = set()
    for commit in ingestion_data.commits:
        for f in commit.files:
            files_to_check.add(f.path)
            
    for dep in ingestion_data.dependency_files:
        files_to_check.add(dep.path)

    findings: list[RiskyFileFinding] = []

    for file_path in files_to_check:
        path_lower = file_path.lower()
        
        # Check all categories
        for risk_type, keywords in RISKY_FILE_KEYWORDS.items():
            if any(kw in path_lower for kw in keywords):
                findings.append(
                    RiskyFileFinding(
                        id=f"rf_{uuid.uuid4().hex[:8]}",
                        file_path=file_path,
                        risk_type=risk_type,
                        reason=f"File path matched heuristic for {risk_type}"
                    )
                )

    return findings
