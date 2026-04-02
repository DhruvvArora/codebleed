"""
RepoGuard — Graph Result Formatter.

Converts raw Neo4j query records into normalized objects used by the services.
"""

from typing import Any, List, Dict
from neo4j.graph import Node, Relationship, Path

def format_node(node: Node) -> Dict[str, Any]:
    """Extract properties and labels from a Neo4j Node."""
    props = dict(node)
    props["_id"] = node.id
    props["_labels"] = list(node.labels)
    # Determine a friendly name/id
    props["FriendlyId"] = props.get("repo_id") or props.get("sha") or props.get("file_id") or \
                        props.get("dependency_id") or props.get("risk_id") or props.get("secret_id") or \
                        props.get("endpoint_id") or props.get("tag_id") or props.get("developer_id")
    return props

def format_path(path: Path) -> Dict[str, Any]:
    """Extract node IDs and edge types from a Neo4j Path."""
    return {
        "node_ids": [str(dict(n).get("repo_id") or dict(n).get("sha") or dict(n).get("file_id") or 
                         dict(n).get("dependency_id") or dict(n).get("risk_id") or dict(n).get("secret_id") or 
                         dict(n).get("endpoint_id") or dict(n).get("tag_id") or 
                         dict(n).get("developer_id") or n.id) for n in path.nodes],
        "edge_types": [rel.type for rel in path.relationships],
        "nodes": [format_node(n) for n in path.nodes]
    }
