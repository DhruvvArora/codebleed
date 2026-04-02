"""
RepoGuard — Graph Queries (Cypher).

Centralized Cypher constants for Component 4 threat intelligence.
All queries should be repository-scoped via repository_url.
"""

# Finds paths from Endpoint -> ... -> (Secret | VulnerabilityCandidate | RiskyFileTag)
# We use shortestPath for performance or ALL paths at depth 6 for demo richness.
GET_ATTACK_PATHS = """
MATCH (repo:Repository {url: $repository_url})
MATCH (e:Endpoint)-[:EXPOSES]-(f:File)-[:BELONGS_TO]->(repo)
MATCH (target)
WHERE (target:Secret OR target:VulnerabilityCandidate OR target:RiskyFileTag)
MATCH path = shortestPath((e)-[*..6]-(target))
WHERE all(rel IN relationships(path) WHERE type(rel) IN ['EXPOSES', 'IMPORTS', 'HAS_RISK', 'CONTAINS_SECRET', 'TAGGED_AS', 'MODIFIED'])
RETURN path
LIMIT $limit
"""

# Finds dependencies with the most risk connections (Blast Radius)
GET_TOP_DEPENDENCY_RISKS = """
MATCH (repo:Repository {url: $repository_url})
MATCH (f:File)-[:BELONGS_TO]->(repo)
MATCH (f)-[:IMPORTS]->(d:Dependency)-[:HAS_RISK]->(v:VulnerabilityCandidate)
WITH d, count(distinct v) as risk_count, collect(distinct v.reason) as reasons
RETURN d.dependency_id as id, d.name as name, risk_count as connected_risk_count, 
       "Influences " + risk_count + " vulnerability candidates: " + apoc.text.join(reasons, ", ") as reason
ORDER BY risk_count DESC
LIMIT $limit
"""

# Finds files with the most risk objects (Secrets, Vulns)
GET_TOP_FILE_RISKS = """
MATCH (repo:Repository {url: $repository_url})
MATCH (f:File)-[:BELONGS_TO]->(repo)
OPTIONAL MATCH (f)-[:CONTAINS_SECRET]->(s:Secret)
OPTIONAL MATCH (f)-[:TAGGED_AS]->(t:RiskyFileTag)
OPTIONAL MATCH (f)-[:IMPORTS]->(d:Dependency)-[:HAS_RISK]->(v:VulnerabilityCandidate)
WITH f, (count(distinct s) + count(distinct t) + count(distinct v)) as risk_count
WHERE risk_count > 0
RETURN f.file_id as id, f.path as name, risk_count as connected_risk_count, 
       "Contains " + risk_count + " associated risk objects (secrets, tags, or vulnerable dependencies)" as reason
ORDER BY risk_count DESC
LIMIT $limit
"""

# Find commits/devs most associated with risks
GET_ROOT_CAUSE_ANALYSIS = """
MATCH (repo:Repository {url: $repository_url})
MATCH (d:Developer)-[:PUSHED]->(c:Commit)-[:IN_REPO]->(repo)
MATCH (c)-[:MODIFIED]->(f:File)
MATCH (f)-[r]->(risk)
WHERE type(r) IN ['CONTAINS_SECRET', 'HAS_RISK', 'TAGGED_AS'] 
      OR (type(r) = 'IMPORTS' AND (risk)-[:HAS_RISK]->())
WITH c, d, count(distinct risk) as risk_links
WHERE risk_links > 0
RETURN c.sha as commit_sha, d.name as developer_name, d.email as developer_email, 
       risk_links, "Associated with " + risk_links + " security-sensitive nodes via modified files" as reason
ORDER BY risk_links DESC
LIMIT $limit
"""

# Find "bottleneck" nodes for fix candidates
GET_FIX_CANDIDATES = """
MATCH (repo:Repository {url: $repository_url})
MATCH (e:Endpoint)-[:EXPOSES]-(f:File)-[:BELONGS_TO]->(repo)
MATCH (target) WHERE (target:Secret OR target:VulnerabilityCandidate)
MATCH path = shortestPath((e)-[*..6]-(target))
WITH nodes(path) as path_nodes
UNWIND path_nodes as n
WITH n, count(*) as path_occurrence
WHERE labels(n)[0] IN ['Secret', 'Dependency', 'Endpoint']
RETURN n.secret_id as secret_id, n.dependency_id as dep_id, n.endpoint_id as ep_id, 
       labels(n)[0] as label, n.name as name, n.type as type, n.route as route, 
       path_occurrence as estimated_paths_reduced
ORDER BY path_occurrence DESC
LIMIT $limit
"""
