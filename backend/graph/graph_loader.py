"""
RepoGuard — Graph Loader.

Handles inserting nodes and edges into Neo4j using MERGE.
Data objects passed here are flat dicts and edges specifying source/target.
"""

import logging
from graph.neo4j_client import get_neo4j_session

logger = logging.getLogger(__name__)

def load_nodes(label: str, id_property: str, nodes: list[dict]):
    """
    Load a list of node dicts into Neo4j using MERGE on `id_property`.
    """
    if not nodes:
        return 0

    query = f"""
    UNWIND $props_list AS props
    MERGE (n:{label} {{{id_property}: props.{id_property}}})
    SET n += props
    """
    try:
        with get_neo4j_session() as session:
            result = session.run(query, props_list=nodes)
            summary = result.consume()
            return summary.counters.nodes_created + summary.counters.properties_set
    except Exception as e:
        logger.error(f"Error loading nodes for {label}: {e}")
        return 0


def load_relationships(
    rel_type: str, 
    source_label: str, source_id_prop: str,
    target_label: str, target_id_prop: str,
    edges: list[tuple[str, str]]
):
    """
    Load relationships into Neo4j using MERGE.
    `edges` is a list of tuples (source_id, target_id).
    """
    if not edges:
        return 0

    # Build a list of dicts for UNWIND
    edge_props = [{"source_id": s, "target_id": t} for s, t in edges]

    query = f"""
    UNWIND $edge_props AS edge
    MATCH (source:{source_label} {{{source_id_prop}: edge.source_id}})
    MATCH (target:{target_label} {{{target_id_prop}: edge.target_id}})
    MERGE (source)-[r:{rel_type}]->(target)
    """
    try:
        with get_neo4j_session() as session:
            result = session.run(query, edge_props=edge_props)
            summary = result.consume()
            return summary.counters.relationships_created
    except Exception as e:
        logger.error(f"Error loading relationships {rel_type}: {e}")
        return 0
