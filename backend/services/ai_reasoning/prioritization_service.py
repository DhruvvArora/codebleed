"""
RepoGuard — AI Prioritization Service.

Simple deterministic ranking of fix candidates to help the AI model
focus on the most impactful remediations.
"""

from typing import List
from schemas.threat_intelligence import FixCandidate

def rank_fix_candidates(candidates: List[FixCandidate]) -> List[FixCandidate]:
    """Sorts candidates by priority and path reduction impact."""
    # Already partially pre-sorted in Component 4, but here we could add more logic
    return sorted(candidates, key=lambda x: (x.priority, -x.estimated_paths_reduced))

def format_candidates_for_ai(candidates: List[FixCandidate]) -> str:
    """Converts ranked candidates into a simple text list for prompting."""
    lines = []
    for c in candidates:
        lines.append(f"- ID: {c.target_node_id} | Fix: {c.title} | Paths Reduced: {c.estimated_paths_reduced}")
    return "\n".join(lines)
