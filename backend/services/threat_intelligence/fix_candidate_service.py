"""
RepoGuard — Fix Candidate Service.

Generates graph-based fix recommendations based on attack path bottlenecks.
"""

from typing import List
import uuid
from graph.neo4j_client import get_neo4j_session
from graph.graph_queries import GET_FIX_CANDIDATES
from schemas.threat_intelligence import FixCandidate

def generate_fix_candidates(repo_url: str, limit: int = 5) -> List[FixCandidate]:
    candidates = []
    with get_neo4j_session() as session:
        result = session.run(GET_FIX_CANDIDATES, repository_url=repo_url, limit=limit)
        priority_counter = 1
        for record in result:
            label = record["label"]
            target_id = record["secret_id"] or record["dep_id"] or record["ep_id"]
            
            fix_type = f"remediate_{label.lower()}"
            title = f"Fix {label}: {record['name'] or record['route']}"
            description = f"This {label} is part of {record['estimated_paths_reduced']} identified attack paths. Breaking this connection will significantly reduce the attack surface."
            
            candidates.append(FixCandidate(
                fix_id=f"fix_{uuid.uuid4().hex[:8]}",
                fix_type=fix_type,
                target_node_id=target_id,
                title=title,
                description=description,
                estimated_paths_reduced=record["estimated_paths_reduced"],
                priority=priority_counter
            ))
            priority_counter += 1
            
    return candidates
