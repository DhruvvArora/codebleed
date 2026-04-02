"""
RepoGuard — Blast Radius Service.

Identifies high-impact nodes (dependencies, files, endpoints).
"""

from typing import List
from graph.neo4j_client import get_neo4j_session
from graph.graph_queries import GET_TOP_DEPENDENCY_RISKS, GET_TOP_FILE_RISKS
from schemas.threat_intelligence import TopRisks, RiskNode

def get_top_risks(repo_url: str, limit: int = 5) -> TopRisks:
    dependencies = []
    files = []
    endpoints = [] # MVP placeholder or separate query

    with get_neo4j_session() as session:
        # 1. Dependency Risks
        result_deps = session.run(GET_TOP_DEPENDENCY_RISKS, repository_url=repo_url, limit=limit)
        for record in result_deps:
            dependencies.append(RiskNode(
                id=record["id"],
                label="Dependency",
                name=record["name"],
                connected_risk_count=record["connected_risk_count"],
                reason=record["reason"]
            ))
            
        # 2. File Risks
        result_files = session.run(GET_TOP_FILE_RISKS, repository_url=repo_url, limit=limit)
        for record in result_files:
            files.append(RiskNode(
                id=record["id"],
                label="File",
                name=record["name"],
                connected_risk_count=record["connected_risk_count"],
                reason=record["reason"]
            ))
            
    return TopRisks(
        dependencies=dependencies,
        files=files,
        endpoints=endpoints
    )
