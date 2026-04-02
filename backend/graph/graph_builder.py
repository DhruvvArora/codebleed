"""
RepoGuard — Graph Builder.

Given a GraphBuildRequest, orchestrates the node and edge factories, 
deduplicates them, and calls the graph_loader to persist them in Neo4j.
Returns the counts of inserted/merged nodes and edges.
"""

from schemas.graph_build import GraphBuildRequest, NodeSummary, EdgeSummary
from graph.graph_models import *
import services.graph_build.node_factory as nf
import services.graph_build.edge_factory as ef
from services.graph_build.dedup_service import dedup_nodes, dedup_edges
from graph.graph_loader import load_nodes, load_relationships

def build_and_load_graph(data: GraphBuildRequest) -> tuple[NodeSummary, EdgeSummary]:
    # --- BUILD ---
    nodes = {
        LABEL_REPOSITORY: [nf.build_repository_node(data)],
        LABEL_DEVELOPER: nf.build_developer_nodes(data),
        LABEL_COMMIT: nf.build_commit_nodes(data),
        LABEL_FILE: nf.build_file_nodes(data),
        LABEL_DEPENDENCY: nf.build_dependency_nodes(data),
        LABEL_VULNERABILITY_CANDIDATE: nf.build_vulnerability_candidate_nodes(data),
        LABEL_SECRET: nf.build_secret_nodes(data),
        LABEL_ENDPOINT: nf.build_endpoint_nodes(data),
        LABEL_RISKY_FILE_TAG: nf.build_risky_file_tag_nodes(data),
    }

    edges = {
        REL_PUSHED: ef.build_pushed_edges(data),
        REL_IN_REPO: ef.build_in_repo_edges(data),
        REL_MODIFIED: ef.build_modified_edges(data),
        REL_BELONGS_TO: ef.build_belongs_to_edges(data),
        REL_IMPORTS: ef.build_imports_edges(data),
        REL_HAS_RISK: ef.build_has_risk_edges(data),
        REL_CONTAINS_SECRET: ef.build_contains_secret_edges(data),
        REL_EXPOSES: ef.build_exposes_edges(data),
        REL_TAGGED_AS: ef.build_tagged_as_edges(data),
        REL_INTRODUCES_SECRET: ef.build_introduces_secret_edges(data)
    }

    # --- DEDUP ---
    nodes[LABEL_REPOSITORY] = dedup_nodes(nodes[LABEL_REPOSITORY], "repo_id")
    nodes[LABEL_DEVELOPER] = dedup_nodes(nodes[LABEL_DEVELOPER], "developer_id")
    nodes[LABEL_COMMIT] = dedup_nodes(nodes[LABEL_COMMIT], "sha")
    nodes[LABEL_FILE] = dedup_nodes(nodes[LABEL_FILE], "file_id")
    nodes[LABEL_DEPENDENCY] = dedup_nodes(nodes[LABEL_DEPENDENCY], "dependency_id")
    nodes[LABEL_VULNERABILITY_CANDIDATE] = dedup_nodes(nodes[LABEL_VULNERABILITY_CANDIDATE], "risk_id")
    nodes[LABEL_SECRET] = dedup_nodes(nodes[LABEL_SECRET], "secret_id")
    nodes[LABEL_ENDPOINT] = dedup_nodes(nodes[LABEL_ENDPOINT], "endpoint_id")
    nodes[LABEL_RISKY_FILE_TAG] = dedup_nodes(nodes[LABEL_RISKY_FILE_TAG], "tag_id")

    for k in edges:
        edges[k] = dedup_edges(edges[k])

    # --- LOAD ---
    n_counts = NodeSummary(
        Repository=load_nodes(LABEL_REPOSITORY, "repo_id", nodes[LABEL_REPOSITORY]),
        Developer=load_nodes(LABEL_DEVELOPER, "developer_id", nodes[LABEL_DEVELOPER]),
        Commit=load_nodes(LABEL_COMMIT, "sha", nodes[LABEL_COMMIT]),
        File=load_nodes(LABEL_FILE, "file_id", nodes[LABEL_FILE]),
        Dependency=load_nodes(LABEL_DEPENDENCY, "dependency_id", nodes[LABEL_DEPENDENCY]),
        VulnerabilityCandidate=load_nodes(LABEL_VULNERABILITY_CANDIDATE, "risk_id", nodes[LABEL_VULNERABILITY_CANDIDATE]),
        Secret=load_nodes(LABEL_SECRET, "secret_id", nodes[LABEL_SECRET]),
        Endpoint=load_nodes(LABEL_ENDPOINT, "endpoint_id", nodes[LABEL_ENDPOINT]),
        RiskyFileTag=load_nodes(LABEL_RISKY_FILE_TAG, "tag_id", nodes[LABEL_RISKY_FILE_TAG])
    )

    e_counts = EdgeSummary(
        PUSHED=load_relationships(REL_PUSHED, LABEL_DEVELOPER, "developer_id", LABEL_COMMIT, "sha", edges[REL_PUSHED]),
        IN_REPO=load_relationships(REL_IN_REPO, LABEL_COMMIT, "sha", LABEL_REPOSITORY, "repo_id", edges[REL_IN_REPO]),
        MODIFIED=load_relationships(REL_MODIFIED, LABEL_COMMIT, "sha", LABEL_FILE, "file_id", edges[REL_MODIFIED]),
        BELONGS_TO=load_relationships(REL_BELONGS_TO, LABEL_FILE, "file_id", LABEL_REPOSITORY, "repo_id", edges[REL_BELONGS_TO]),
        IMPORTS=load_relationships(REL_IMPORTS, LABEL_FILE, "file_id", LABEL_DEPENDENCY, "dependency_id", edges[REL_IMPORTS]),
        HAS_RISK=load_relationships(REL_HAS_RISK, LABEL_DEPENDENCY, "dependency_id", LABEL_VULNERABILITY_CANDIDATE, "risk_id", edges[REL_HAS_RISK]),
        CONTAINS_SECRET=load_relationships(REL_CONTAINS_SECRET, LABEL_FILE, "file_id", LABEL_SECRET, "secret_id", edges[REL_CONTAINS_SECRET]),
        EXPOSES=load_relationships(REL_EXPOSES, LABEL_FILE, "file_id", LABEL_ENDPOINT, "endpoint_id", edges[REL_EXPOSES]),
        TAGGED_AS=load_relationships(REL_TAGGED_AS, LABEL_FILE, "file_id", LABEL_RISKY_FILE_TAG, "tag_id", edges[REL_TAGGED_AS]),
        INTRODUCES_SECRET=load_relationships(REL_INTRODUCES_SECRET, LABEL_COMMIT, "sha", LABEL_SECRET, "secret_id", edges.get(REL_INTRODUCES_SECRET, []))
    )

    return n_counts, e_counts
