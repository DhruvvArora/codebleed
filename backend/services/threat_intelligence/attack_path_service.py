"""
RepoGuard — Attack Path Service.

Executes and processes attack path queries (Endpoint -> ... -> Risk).
"""

import uuid
from typing import List
from graph.neo4j_client import get_neo4j_session
from graph.graph_queries import GET_ATTACK_PATHS
from schemas.threat_intelligence import AttackPath
from services.threat_intelligence.graph_result_formatter import format_path

def classify_severity(node_labels: List[str], edge_types: List[str]) -> str:
    """Heuristic severity classification for a path."""
    labels_set = set(node_labels)
    if "Secret" in labels_set and "Endpoint" in labels_set:
        if "VulnerabilityCandidate" in labels_set:
            return "critical"
        return "high"
    if "VulnerabilityCandidate" in labels_set and "Endpoint" in labels_set:
        return "high"
    if "RiskyFileTag" in labels_set:
        return "medium"
    return "low"

def get_attack_paths(repo_url: str, limit: int = 5) -> List[AttackPath]:
    paths_out = []
    with get_neo4j_session() as session:
        result = session.run(GET_ATTACK_PATHS, repository_url=repo_url, limit=limit)
        for record in result:
            raw_path = record["path"]
            formatted = format_path(raw_path)
            
            # Identify path type and severity
            node_labels = []
            for n in formatted["nodes"]:
                node_labels.extend(n["_labels"])
            
            severity = classify_severity(node_labels, formatted["edge_types"])
            
            paths_out.append(AttackPath(
                path_id=f"path_{uuid.uuid4().hex[:8]}",
                path_type="graph_traversal_path",
                entry_node_id=formatted["node_ids"][0],
                target_node_id=formatted["node_ids"][-1],
                node_ids=formatted["node_ids"],
                edge_types=formatted["edge_types"],
                summary=f"Attack path found from {formatted['node_ids'][0]} to security risk.",
                severity_hint=severity
            ))
    return paths_out
