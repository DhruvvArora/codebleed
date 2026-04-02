"""
RepoGuard — Endpoint Detector.

Identifies potential public-facing routes/endpoints from path hints
and code patterns in file contents (if any are available in raw text).
Since Component 1 primarily passes dependency files, this will also
scan file paths from commit history for hints.
"""

from __future__ import annotations
import uuid
from schemas.repo_ingestion import IngestionResponse
from schemas.security_extraction import EndpointFinding
from utils.security_patterns import ENDPOINT_PATH_HINTS, ENDPOINT_PATTERNS


def detect_endpoints(ingestion_data: IngestionResponse) -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    files_checked = set()

    for commit in ingestion_data.commits:
        for f in commit.files:
            if f.path in files_checked:
                continue
            files_checked.add(f.path)
            
            path_lower = f.path.lower()
            
            # Simple heuristic: if it looks like an API route file path
            is_route_file = any(hint in path_lower for hint in ENDPOINT_PATH_HINTS)
            if is_route_file:
                # In a real tool we'd read the file content. 
                # Since Component 1 doesn't fetch all source code (only dep contents),
                # we infer the endpoint from the file path.
                findings.append(
                    EndpointFinding(
                        id=f"endpoint_{uuid.uuid4().hex[:8]}",
                        route=f"/{f.path}",
                        method="ANY",
                        file_path=f.path,
                        source="file_path_heuristic"
                    )
                )

    return findings
