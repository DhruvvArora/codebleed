"""
RepoGuard — AI Explanation Service.

Simplifies the structured attack paths from Component 4 into natural-language
evidence that can be easily understood by the AI model.
"""

from typing import List
from schemas.threat_intelligence import AttackPath

def summarize_complex_paths(paths: List[AttackPath]) -> str:
    """Creates a concise text summary of the most critical attack paths."""
    if not paths:
        return "No significant attack paths discovered by the graph reasoning engine."

    summary_lines = []
    for i, path in enumerate(paths[:3], 1): # Top 3 paths
        severity = path.severity_hint.upper()
        nodes_str = " -> ".join(path.node_ids)
        summary_lines.append(f"Attack Path {i} [{severity}]: {nodes_str}")
        summary_lines.append(f"  Types: {' -> '.join(path.edge_types)}")
    
    return "\n".join(summary_lines)
