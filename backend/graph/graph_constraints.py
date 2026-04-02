"""
RepoGuard — Neo4j Graph Constraints.

Ensures uniqueness and builds indexes for the core entities to optimize MERGE.
"""

import logging
from graph.neo4j_client import get_neo4j_session

logger = logging.getLogger(__name__)

CONSTRAINTS = [
    ("constraint_repository_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Repository) REQUIRE r.repo_id IS UNIQUE"),
    ("constraint_developer_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Developer) REQUIRE d.developer_id IS UNIQUE"),
    ("constraint_commit_sha", "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Commit) REQUIRE c.sha IS UNIQUE"),
    ("constraint_file_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (f:File) REQUIRE f.file_id IS UNIQUE"),
    ("constraint_dependency_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Dependency) REQUIRE d.dependency_id IS UNIQUE"),
    ("constraint_vulnerability_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (v:VulnerabilityCandidate) REQUIRE v.risk_id IS UNIQUE"),
    ("constraint_secret_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Secret) REQUIRE s.secret_id IS UNIQUE"),
    ("constraint_endpoint_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.endpoint_id IS UNIQUE"),
    ("constraint_risky_tag_id", "CREATE CONSTRAINT IF NOT EXISTS FOR (t:RiskyFileTag) REQUIRE t.tag_id IS UNIQUE"),
]

def setup_constraints():
    """Initialise constraints and indexes in the Neo4j database."""
    logger.info("Setting up Neo4j constraints/indexes...")
    try:
        with get_neo4j_session() as session:
            for name, query in CONSTRAINTS:
                session.run(query)
                logger.info(f"Ensured constraint/index step: {name}")
    except Exception as e:
        logger.error(f"Failed to setup Neo4j constraints: {e}")
        # Not raising if Neo4j is purely optional or failing early; depending on MVP needs.
