"""
RepoGuard — Dedup Service.

Removes duplicate items from lists of dicts or tuples before passing to the graph loader.
"""

def dedup_nodes(nodes: list[dict], id_field: str) -> list[dict]:
    seen = set()
    deduped = []
    for node in nodes:
        key = node.get(id_field)
        if key and key not in seen:
            seen.add(key)
            deduped.append(node)
    return deduped

def dedup_edges(edges: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return list(set(edges))
