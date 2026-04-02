"""
RepoGuard — Edge Factory.

Builds lists of relationships represented as (source_id, target_id) tuples.
"""

from schemas.graph_build import GraphBuildRequest

def get_repo_id(data: GraphBuildRequest) -> str:
    repo = data.ingestion_data.repository
    return f"repo::{repo.owner}/{repo.name}"

def get_file_id(data: GraphBuildRequest, path: str) -> str:
    repo_url = data.ingestion_data.repository.url
    return f"file::{repo_url}::{path}"

def build_pushed_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(Developer)-[:PUSHED]->(Commit)"""
    edges = []
    for commit in data.ingestion_data.commits:
        identifier = commit.author_email or commit.author_name
        dev_id = f"dev::{identifier}"
        edges.append((dev_id, commit.sha))
    return edges

def build_in_repo_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(Commit)-[:IN_REPO]->(Repository)"""
    edges = []
    repo_id = get_repo_id(data)
    for commit in data.ingestion_data.commits:
        edges.append((commit.sha, repo_id))
    return edges

def build_modified_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(Commit)-[:MODIFIED]->(File)"""
    edges = []
    for commit in data.ingestion_data.commits:
        for f in commit.files:
            file_id = get_file_id(data, f.path)
            edges.append((commit.sha, file_id))
    return edges

def build_belongs_to_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(File)-[:BELONGS_TO]->(Repository)"""
    edges = []
    repo_id = get_repo_id(data)
    
    # Need to cover all unique files
    file_paths = set()
    for commit in data.ingestion_data.commits:
        for f in commit.files:
            file_paths.add(f.path)
    for ep in data.security_data.endpoints:
        file_paths.add(ep.file_path)
    for rft in data.security_data.risky_files:
        file_paths.add(rft.file_path)
            
    for path in file_paths:
        file_id = get_file_id(data, path)
        edges.append((file_id, repo_id))
    return edges

def build_imports_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(File)-[:IMPORTS]->(Dependency)"""
    edges = []
    repo_name = data.ingestion_data.repository.name
    for dep in data.security_data.dependencies:
        dep_id = f"dep::{repo_name}::{dep.name}@{dep.version}"
        file_id = get_file_id(data, dep.source_file)
        edges.append((file_id, dep_id))
    return edges

def build_has_risk_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(Dependency)-[:HAS_RISK]->(VulnerabilityCandidate)"""
    edges = []
    repo_name = data.ingestion_data.repository.name
    for dep in data.security_data.dependencies:
        if dep.risk_status == "risk_candidate":
            dep_id = f"dep::{repo_name}::{dep.name}@{dep.version}"
            risk_id = f"risk::{dep.name}@{dep.version}"
            edges.append((dep_id, risk_id))
    return edges

def build_contains_secret_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(File)-[:CONTAINS_SECRET]->(Secret)"""
    edges = []
    for sec in data.security_data.secrets:
        if sec.file_path:
            file_id = get_file_id(data, sec.file_path)
            sec_id = f"secret::{sec.file_path}::{sec.type}::{sec.id}"
            edges.append((file_id, sec_id))
    return edges

def build_exposes_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(File)-[:EXPOSES]->(Endpoint)"""
    edges = []
    for ep in data.security_data.endpoints:
        file_id = get_file_id(data, ep.file_path)
        ep_id = f"endpoint::{ep.file_path}::{ep.method}::{ep.route}"
        edges.append((file_id, ep_id))
    return edges

def build_tagged_as_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(File)-[:TAGGED_AS]->(RiskyFileTag)"""
    edges = []
    for tag in data.security_data.risky_files:
        file_id = get_file_id(data, tag.file_path)
        tag_id = f"tag::{tag.file_path}::{tag.risk_type}"
        edges.append((file_id, tag_id))
    return edges

# Optional relationships mapping commits directly to discovered findings
def build_introduces_secret_edges(data: GraphBuildRequest) -> list[tuple[str, str]]:
    """(Commit)-[:INTRODUCES_SECRET]->(Secret)"""
    edges = []
    for sec in data.security_data.secrets:
        if sec.commit_sha:
            sec_id = f"secret::{sec.file_path or 'unknown_file'}::{sec.type}::{sec.id}"
            edges.append((sec.commit_sha, sec_id))
    return edges
