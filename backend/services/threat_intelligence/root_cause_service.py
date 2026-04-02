"""
RepoGuard — Root Cause Service.

Maps security findings back to commits and developers.
"""

from typing import List
from graph.neo4j_client import get_neo4j_session
from graph.graph_queries import GET_ROOT_CAUSE_ANALYSIS
from schemas.threat_intelligence import RootCause

def analyze_root_causes(repo_url: str, limit: int = 5) -> List[RootCause]:
    causes = []
    with get_neo4j_session() as session:
        result = session.run(GET_ROOT_CAUSE_ANALYSIS, repository_url=repo_url, limit=limit)
        for record in result:
            causes.append(RootCause(
                commit_sha=record["commit_sha"],
                developer_name=record["developer_name"],
                developer_email=record["developer_email"],
                risk_links=record["risk_links"],
                reason=record["reason"]
            ))
    return causes
