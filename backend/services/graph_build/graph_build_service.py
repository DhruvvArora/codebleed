"""
RepoGuard — Graph Build Service.

Top-level orchestrator for Component 3. Ensures constraints are set,
invokes the builder/loader, and returns the final GraphBuildResponse.
"""

from __future__ import annotations
import logging
from schemas.graph_build import GraphBuildRequest, GraphBuildResponse, GraphSummaryDict
from graph.graph_constraints import setup_constraints
from graph.graph_builder import build_and_load_graph

logger = logging.getLogger(__name__)

def build_graph(data: GraphBuildRequest) -> GraphBuildResponse:
    logger.info("Starting Graph Build for Repo (Component 3)...")

    # Ensure Neo4j setup correctly (indexes, constraints)
    setup_constraints()

    # Orchestrate factory and loader logic
    node_summary, edge_summary = build_and_load_graph(data)

    graph_summary = GraphSummaryDict(
        nodes_created_or_merged=node_summary,
        relationships_created_or_merged=edge_summary
    )

    logger.info("Graph build completed successfully.")

    return GraphBuildResponse(
        repository=data.ingestion_data.repository,
        graph_summary=graph_summary
    )
