"""
RepoGuard — Node Factory.

Converts structured input (Component 1 + 2) into normalized flat dicts 
for node insertion into Neo4j. Handles generating stable IDs.
"""

from schemas.graph_build import GraphBuildRequest
from graph.graph_models import *

def build_repository_node(data: GraphBuildRequest) -> dict:
    repo = data.ingestion_data.repository
    return {
        "label": LABEL_REPOSITORY,
        "repo_id": f"repo::{repo.owner}/{repo.name}",
        "name": repo.name,
        "owner": repo.owner,
        "url": repo.url,
        "default_branch": repo.default_branch
    }

def build_developer_nodes(data: GraphBuildRequest) -> list[dict]:
    # Use emails as developer ID to deduplicate correctly
    devs = {}
    for commit in data.ingestion_data.commits:
        identifier = commit.author_email or commit.author_name
        dev_id = f"dev::{identifier}"
        if dev_id not in devs:
            devs[dev_id] = {
                "label": LABEL_DEVELOPER,
                "developer_id": dev_id,
                "name": commit.author_name,
                "email": commit.author_email
            }
    return list(devs.values())

def build_commit_nodes(data: GraphBuildRequest) -> list[dict]:
    commits = []
    for commit in data.ingestion_data.commits:
        commits.append({
            "label": LABEL_COMMIT,
            "sha": commit.sha,
            "message": commit.message,
            "date": commit.date
        })
    return commits

def build_file_nodes(data: GraphBuildRequest) -> list[dict]:
    files = {}
    repo_url = data.ingestion_data.repository.url
    
    # Files from commits
    for commit in data.ingestion_data.commits:
        for f in commit.files:
            file_id = f"file::{repo_url}::{f.path}"
            if file_id not in files:
                files[file_id] = {
                    "label": LABEL_FILE,
                    "file_id": file_id,
                    "path": f.path
                }
                
    # Files from risky tags / endpoint scanning (if not backed by a commit)
    for tag in data.security_data.risky_files:
        file_id = f"file::{repo_url}::{tag.file_path}"
        if file_id not in files:
            files[file_id] = {"label": LABEL_FILE, "file_id": file_id, "path": tag.file_path}
            
    # Files from endpoints
    for end in data.security_data.endpoints:
        file_id = f"file::{repo_url}::{end.file_path}"
        if file_id not in files:
            files[file_id] = {"label": LABEL_FILE, "file_id": file_id, "path": end.file_path}

    return list(files.values())

def build_dependency_nodes(data: GraphBuildRequest) -> list[dict]:
    deps = {}
    repo_name = data.ingestion_data.repository.name
    for dep in data.security_data.dependencies:
        dep_id = f"dep::{repo_name}::{dep.name}@{dep.version}"
        if dep_id not in deps:
            deps[dep_id] = {
                "label": LABEL_DEPENDENCY,
                "dependency_id": dep_id,
                "name": dep.name,
                "version": dep.version,
                "source_file": dep.source_file
            }
    return list(deps.values())

def build_vulnerability_candidate_nodes(data: GraphBuildRequest) -> list[dict]:
    vulns = {}
    for dep in data.security_data.dependencies:
        if dep.risk_status == "risk_candidate":
            risk_id = f"risk::{dep.name}@{dep.version}"
            if risk_id not in vulns:
                vulns[risk_id] = {
                    "label": LABEL_VULNERABILITY_CANDIDATE,
                    "risk_id": risk_id,
                    "name": f"Risk for {dep.name}",
                    "risk_status": dep.risk_status,
                    "reason": dep.reason or ""
                }
    return list(vulns.values())

def build_secret_nodes(data: GraphBuildRequest) -> list[dict]:
    secrets = []
    for sec in data.security_data.secrets:
        # secret_id needs to be stable representing the occurrence
        file_part = sec.file_path or "unknown_file"
        sec_id = f"secret::{file_part}::{sec.type}::{sec.id}"
        secrets.append({
            "label": LABEL_SECRET,
            "secret_id": sec_id,
            "type": sec.type,
            "value_preview": sec.value_preview,
            "source": sec.source
        })
    return secrets

def build_endpoint_nodes(data: GraphBuildRequest) -> list[dict]:
    endpoints = []
    for ep in data.security_data.endpoints:
        ep_id = f"endpoint::{ep.file_path}::{ep.method}::{ep.route}"
        endpoints.append({
            "label": LABEL_ENDPOINT,
            "endpoint_id": ep_id,
            "route": ep.route,
            "method": ep.method,
            "source": ep.source
        })
    return endpoints

def build_risky_file_tag_nodes(data: GraphBuildRequest) -> list[dict]:
    tags = []
    for tag in data.security_data.risky_files:
        tag_id = f"tag::{tag.file_path}::{tag.risk_type}"
        tags.append({
            "label": LABEL_RISKY_FILE_TAG,
            "tag_id": tag_id,
            "risk_type": tag.risk_type,
            "reason": tag.reason
        })
    return tags
