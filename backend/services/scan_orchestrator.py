from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from schemas.ai_reasoning import AIReasoningRequest
from schemas.graph_build import GraphBuildRequest
from schemas.repo_ingestion import IngestionRequest, IngestionResponse
from schemas.security_extraction import SecurityExtractionResponse
from schemas.threat_intelligence import (
    AttackPath,
    FixCandidate,
    IntelligenceSummary,
    RiskNode,
    RootCause,
    ThreatIntelligenceRequest,
    ThreatIntelligenceResponse,
    TopRisks,
)
from services.graph_build.dedup_service import dedup_edges, dedup_nodes
import services.graph_build.node_factory as nf
import services.graph_build.edge_factory as ef

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
LABEL_SCORE = {
    "Repository": 8,
    "Developer": 12,
    "Commit": 14,
    "File": 20,
    "Dependency": 28,
    "VulnerabilityCandidate": 78,
    "Secret": 88,
    "Endpoint": 42,
    "RiskyFileTag": 46,
}
LABEL_SEVERITY = {
    "Repository": "low",
    "Developer": "low",
    "Commit": "low",
    "File": "low",
    "Dependency": "medium",
    "VulnerabilityCandidate": "high",
    "Secret": "critical",
    "Endpoint": "medium",
    "RiskyFileTag": "medium",
}
UI_LABEL_MAP = {
    "VulnerabilityCandidate": "Vulnerability",
    "RiskyFileTag": "RiskFinding",
}
SEVERITY_BASE_SCORE = {"low": 22, "medium": 48, "high": 72, "critical": 90}


async def run_scan_pipeline(request: Any) -> Dict[str, Any]:
    from services.repo_ingestion.ingestion_service import ingest_repo
    from services.security_extraction.extraction_service import extract_security_findings

    ingestion_request = IngestionRequest(
        repo_url=request.repo_url,
        branch=request.branch,
        max_commits=request.max_commits,
    )
    ingestion = await ingest_repo(ingestion_request)
    security = extract_security_findings(ingestion)
    graph_request = GraphBuildRequest(ingestion_data=ingestion, security_data=security)

    graph_build_status = "local"
    graph_build_error = None

    ui_graph = build_ui_graph(graph_request)

    threat_request = ThreatIntelligenceRequest(
        repository_url=ingestion.repository.url,
        max_paths=request.max_paths,
        max_risks=request.max_risks,
        include_fix_candidates=True,
    )

    threat_status = "local"
    threat = build_fallback_threat_intelligence(ingestion, security)

    try:
        from services.ai_reasoning.ai_reasoning_service import perform_ai_reasoning

        ai_result = perform_ai_reasoning(
            AIReasoningRequest(
                repository=model_to_dict(ingestion.repository),
                threat_intelligence=threat,
                report_style="analyst",
                max_recommendations=4,
                include_developer_summary=True,
            )
        )
    except Exception as exc:
        logger.warning("AI reasoning failed, using deterministic report adapter: %s", exc)
        ai_result = None

    response = adapt_to_ui_payload(
        ingestion=ingestion,
        security=security,
        threat=threat,
        ui_graph=ui_graph,
        ai_result=ai_result,
        graph_build_status=graph_build_status,
        graph_build_error=graph_build_error,
        threat_status=threat_status,
    )
    return response


def model_to_dict(model: Any) -> Any:
    if model is None:
        return None
    if hasattr(model, "model_dump"):
        return model.model_dump()
    if hasattr(model, "dict"):
        return model.dict()
    if isinstance(model, list):
        return [model_to_dict(item) for item in model]
    if isinstance(model, dict):
        return {key: model_to_dict(value) for key, value in model.items()}
    return model


def build_ui_graph(graph_request: GraphBuildRequest) -> Dict[str, List[Dict[str, Any]]]:
    nodes_by_label = {
        "Repository": dedup_nodes([nf.build_repository_node(graph_request)], "repo_id"),
        "Developer": dedup_nodes(nf.build_developer_nodes(graph_request), "developer_id"),
        "Commit": dedup_nodes(nf.build_commit_nodes(graph_request), "sha"),
        "File": dedup_nodes(nf.build_file_nodes(graph_request), "file_id"),
        "Dependency": dedup_nodes(nf.build_dependency_nodes(graph_request), "dependency_id"),
        "VulnerabilityCandidate": dedup_nodes(
            nf.build_vulnerability_candidate_nodes(graph_request), "risk_id"
        ),
        "Secret": dedup_nodes(nf.build_secret_nodes(graph_request), "secret_id"),
        "Endpoint": dedup_nodes(nf.build_endpoint_nodes(graph_request), "endpoint_id"),
        "RiskyFileTag": dedup_nodes(nf.build_risky_file_tag_nodes(graph_request), "tag_id"),
    }

    edges_by_type = {
        "PUSHED": dedup_edges(ef.build_pushed_edges(graph_request)),
        "IN_REPO": dedup_edges(ef.build_in_repo_edges(graph_request)),
        "MODIFIED": dedup_edges(ef.build_modified_edges(graph_request)),
        "BELONGS_TO": dedup_edges(ef.build_belongs_to_edges(graph_request)),
        "IMPORTS": dedup_edges(ef.build_imports_edges(graph_request)),
        "HAS_RISK": dedup_edges(ef.build_has_risk_edges(graph_request)),
        "CONTAINS_SECRET": dedup_edges(ef.build_contains_secret_edges(graph_request)),
        "EXPOSES": dedup_edges(ef.build_exposes_edges(graph_request)),
        "TAGGED_AS": dedup_edges(ef.build_tagged_as_edges(graph_request)),
        "INTRODUCES_SECRET": dedup_edges(ef.build_introduces_secret_edges(graph_request)),
    }

    nodes: List[Dict[str, Any]] = []
    for label, group in nodes_by_label.items():
        for node in group:
            node_id = get_node_id(label, node)
            name = get_node_name(label, node)
            nodes.append(
                {
                    "id": node_id,
                    "label": UI_LABEL_MAP.get(label, label),
                    "raw_label": label,
                    "name": name,
                }
            )

    edges: List[Dict[str, Any]] = []
    for rel_type, rels in edges_by_type.items():
        for source, target in rels:
            edges.append(
                {
                    "id": make_edge_id(rel_type, source, target),
                    "source": source,
                    "target": target,
                    "type": rel_type,
                }
            )

    return {"nodes": nodes, "edges": edges}


def build_fallback_threat_intelligence(
    ingestion: IngestionResponse,
    security: SecurityExtractionResponse,
) -> ThreatIntelligenceResponse:
    repo_url = ingestion.repository.url
    file_to_secrets: Dict[str, List[Any]] = defaultdict(list)
    for secret in security.secrets:
        if secret.file_path:
            file_to_secrets[secret.file_path].append(secret)

    file_to_deps: Dict[str, List[Any]] = defaultdict(list)
    for dep in security.dependencies:
        if dep.risk_status == "risk_candidate":
            file_to_deps[dep.source_file].append(dep)

    file_to_tags: Dict[str, List[Any]] = defaultdict(list)
    for tag in security.risky_files:
        file_to_tags[tag.file_path].append(tag)

    attack_paths: List[AttackPath] = []
    path_counter = 1
    node_frequency: Counter[str] = Counter()
    fix_targets: Counter[Tuple[str, str, str]] = Counter()

    for endpoint in security.endpoints:
        file_id = f"file::{repo_url}::{endpoint.file_path}"
        endpoint_id = f"endpoint::{endpoint.file_path}::{endpoint.method}::{endpoint.route}"

        for secret in file_to_secrets.get(endpoint.file_path, []):
            secret_id = f"secret::{secret.file_path or 'unknown_file'}::{secret.type}::{secret.id}"
            path = AttackPath(
                path_id=f"path_fallback_{path_counter}",
                path_type="endpoint_to_secret",
                entry_node_id=endpoint_id,
                target_node_id=secret_id,
                node_ids=[endpoint_id, file_id, secret_id],
                edge_types=["EXPOSES", "CONTAINS_SECRET"],
                summary=f"Public endpoint {endpoint.method} {endpoint.route} leads to a file containing a detected secret.",
                severity_hint="critical",
            )
            path_counter += 1
            attack_paths.append(path)
            node_frequency.update(path.node_ids)
            fix_targets[(secret_id, "remediate_secret", f"Rotate secret in {endpoint.file_path}")] += 1

        for dep in file_to_deps.get(endpoint.file_path, []):
            dep_id = f"dep::{ingestion.repository.name}::{dep.name}@{dep.version}"
            risk_id = f"risk::{dep.name}@{dep.version}"
            path = AttackPath(
                path_id=f"path_fallback_{path_counter}",
                path_type="endpoint_to_vulnerability",
                entry_node_id=endpoint_id,
                target_node_id=risk_id,
                node_ids=[endpoint_id, file_id, dep_id, risk_id],
                edge_types=["EXPOSES", "IMPORTS", "HAS_RISK"],
                summary=f"Endpoint {endpoint.method} {endpoint.route} reaches a dependency with a known risk candidate: {dep.name}@{dep.version}.",
                severity_hint="high",
            )
            path_counter += 1
            attack_paths.append(path)
            node_frequency.update(path.node_ids)
            fix_targets[(dep_id, "patch_dependency", f"Patch dependency {dep.name}@{dep.version}")] += 1

        for tag in file_to_tags.get(endpoint.file_path, []):
            tag_id = f"tag::{tag.file_path}::{tag.risk_type}"
            path = AttackPath(
                path_id=f"path_fallback_{path_counter}",
                path_type="endpoint_to_risky_file",
                entry_node_id=endpoint_id,
                target_node_id=tag_id,
                node_ids=[endpoint_id, file_id, tag_id],
                edge_types=["EXPOSES", "TAGGED_AS"],
                summary=f"Endpoint {endpoint.method} {endpoint.route} is connected to a file tagged as risky ({tag.risk_type}).",
                severity_hint="medium",
            )
            path_counter += 1
            attack_paths.append(path)
            node_frequency.update(path.node_ids)
            fix_targets[(tag_id, "harden_file", f"Harden risky file {tag.file_path}")] += 1

    top_dependencies = sorted(
        [
            RiskNode(
                id=f"dep::{ingestion.repository.name}::{dep.name}@{dep.version}",
                label="Dependency",
                name=f"{dep.name}@{dep.version}",
                connected_risk_count=1,
                reason=dep.reason or "Dependency flagged as a risk candidate.",
            )
            for dep in security.dependencies
            if dep.risk_status == "risk_candidate"
        ],
        key=lambda item: item.name,
    )[:5]

    file_risk_count: Counter[str] = Counter()
    for secret in security.secrets:
        if secret.file_path:
            file_risk_count[secret.file_path] += 1
    for dep in security.dependencies:
        if dep.risk_status == "risk_candidate":
            file_risk_count[dep.source_file] += 1
    for tag in security.risky_files:
        file_risk_count[tag.file_path] += 1

    top_files = [
        RiskNode(
            id=f"file::{repo_url}::{path}",
            label="File",
            name=path,
            connected_risk_count=count,
            reason=f"Linked to {count} security finding(s).",
        )
        for path, count in file_risk_count.most_common(5)
    ]

    root_causes = [
        RootCause(
            commit_sha=secret.commit_sha or "unknown",
            developer_name=secret.author_name or "unknown",
            developer_email="unknown",
            risk_links=1,
            reason=f"Commit history suggests a secret was introduced via {secret.file_path or 'unknown file'}.",
        )
        for secret in security.secrets[:5]
    ]

    fix_candidates: List[FixCandidate] = []
    for index, ((target_node_id, fix_type, title), count) in enumerate(
        fix_targets.most_common(5), start=1
    ):
        fix_candidates.append(
            FixCandidate(
                fix_id=f"fix_fallback_{index}",
                fix_type=fix_type,
                target_node_id=target_node_id,
                title=title,
                description=f"Breaking this node removes or weakens {count} locally inferred attack path(s).",
                estimated_paths_reduced=count,
                priority=index,
            )
        )

    summary = IntelligenceSummary(
        attack_paths_found=len(attack_paths),
        top_dependency_risks=len(top_dependencies),
        top_file_risks=len(top_files),
        top_endpoint_risks=0,
        root_causes_found=len(root_causes),
        fix_candidates_found=len(fix_candidates),
    )

    return ThreatIntelligenceResponse(
        repository={"url": repo_url},
        attack_paths=attack_paths,
        top_risks=TopRisks(dependencies=top_dependencies, files=top_files, endpoints=[]),
        root_causes=root_causes,
        fix_candidates=fix_candidates,
        summary=summary,
    )


def adapt_to_ui_payload(
    *,
    ingestion: IngestionResponse,
    security: SecurityExtractionResponse,
    threat: ThreatIntelligenceResponse,
    ui_graph: Dict[str, List[Dict[str, Any]]],
    ai_result: Any,
    graph_build_status: str,
    graph_build_error: str | None,
    threat_status: str,
) -> Dict[str, Any]:
    path_entries = [adapt_attack_path(path) for path in threat.attack_paths]
    path_stats = build_path_stats(path_entries)
    graph_payload = decorate_graph(ui_graph, path_stats)
    findings = adapt_findings(security)
    top_risks = adapt_top_risks(threat)
    fix_candidates = adapt_fix_candidates(threat.fix_candidates)

    summary_risk = compute_overall_risk_score(path_entries, findings, top_risks)
    ai_report = adapt_ai_report(ai_result, threat, security, summary_risk)

    return {
        "repository": model_to_dict(ingestion.repository),
        "status": "scan_completed",
        "pipeline": {
            "graph_build_status": graph_build_status,
            "graph_build_error": graph_build_error,
            "threat_status": threat_status,
        },
        "summary": {
            "risk_score": summary_risk,
            "attack_paths_found": len(path_entries),
            "secrets_found": len(findings["secrets"]),
            "vulnerabilities_found": len(findings["vulnerabilities"]),
            "endpoints_found": len(findings["endpoints"]),
            "fix_candidates_found": len(fix_candidates),
        },
        "graph": graph_payload,
        "attack_paths": path_entries,
        "top_risks": top_risks,
        "findings": findings,
        "fix_candidates": fix_candidates,
        "ai_report": ai_report,
    }


def adapt_attack_path(path: AttackPath) -> Dict[str, Any]:
    severity = normalize_severity(path.severity_hint)
    edge_ids = []
    for index, rel_type in enumerate(path.edge_types):
        if index + 1 >= len(path.node_ids):
            break
        source = path.node_ids[index]
        target = path.node_ids[index + 1]
        edge_ids.append(make_edge_id(rel_type, source, target))

    return {
        "path_id": path.path_id,
        "path_type": path.path_type,
        "entry_node_id": path.entry_node_id,
        "target_node_id": path.target_node_id,
        "node_ids": path.node_ids,
        "edge_ids": edge_ids,
        "edge_types": path.edge_types,
        "summary": path.summary,
        "severity": severity,
        "risk_score": score_path(severity, len(path.node_ids)),
    }


def build_path_stats(path_entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "severity": "low"})
    for path in path_entries:
        for node_id in path["node_ids"]:
            stats[node_id]["count"] += 1
            stats[node_id]["severity"] = max_severity(stats[node_id]["severity"], path["severity"])
    return stats


def decorate_graph(
    ui_graph: Dict[str, List[Dict[str, Any]]],
    path_stats: Dict[str, Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    nodes = []
    for node in ui_graph["nodes"]:
        raw_label = node.get("raw_label", node["label"])
        default_severity = LABEL_SEVERITY.get(raw_label, "low")
        default_score = LABEL_SCORE.get(raw_label, 15)
        stat = path_stats.get(node["id"], {"count": 0, "severity": default_severity})
        severity = max_severity(default_severity, stat["severity"])
        risk_score = min(100, max(default_score, SEVERITY_BASE_SCORE[severity] + stat["count"] * 6))
        nodes.append(
            {
                **node,
                "severity": severity,
                "risk_score": risk_score,
            }
        )
    return {"nodes": nodes, "edges": ui_graph["edges"]}


def adapt_findings(security: SecurityExtractionResponse) -> Dict[str, Any]:
    secrets = []
    for secret in security.secrets:
        severity = "critical" if "private" in secret.type.lower() or "token" in secret.type.lower() else "high"
        secrets.append(
            {
                "id": secret.id,
                "type": secret.type,
                "file": secret.file_path or "unknown",
                "developer": secret.author_name or "unknown",
                "severity": severity,
                "value_preview": secret.value_preview,
            }
        )

    vulnerabilities = []
    for dep in security.dependencies:
        if dep.risk_status != "risk_candidate":
            continue
        severity = "high" if any(word in (dep.reason or "").lower() for word in ["critical", "rce", "deserialization"]) else "medium"
        vulnerabilities.append(
            {
                "id": dep.id,
                "cve": f"Risk candidate · {dep.name}@{dep.version}",
                "dependency": dep.name,
                "affected_files": [dep.source_file],
                "severity": severity,
                "reason": dep.reason or "Dependency flagged by heuristic risk detection.",
            }
        )

    endpoints = []
    for endpoint in security.endpoints:
        route_lower = endpoint.route.lower()
        public_facing = route_lower.startswith("/")
        severity = "high" if any(term in route_lower for term in ["admin", "auth", "login", "token", "upload"]) else "medium"
        endpoints.append(
            {
                "id": endpoint.id,
                "method": endpoint.method,
                "route": endpoint.route,
                "file": endpoint.file_path,
                "public_facing": public_facing,
                "severity": severity,
            }
        )

    return {
        "secrets": secrets,
        "vulnerabilities": vulnerabilities,
        "endpoints": endpoints,
    }


def adapt_top_risks(threat: ThreatIntelligenceResponse) -> List[Dict[str, Any]]:
    combined = []
    for risk in list(threat.top_risks.dependencies) + list(threat.top_risks.files) + list(threat.top_risks.endpoints):
        score = min(100, 35 + risk.connected_risk_count * 12)
        severity = severity_from_score(score)
        combined.append(
            {
                "id": risk.id,
                "title": risk.name,
                "label": risk.label,
                "reason": risk.reason,
                "severity": severity,
                "risk_score": score,
            }
        )
    combined.sort(key=lambda item: item["risk_score"], reverse=True)
    return combined[:6]


def adapt_fix_candidates(fix_candidates: Iterable[FixCandidate]) -> List[Dict[str, Any]]:
    adapted = []
    for fix in fix_candidates:
        adapted.append(
            {
                "fix_id": fix.fix_id,
                "fix_type": fix.fix_type,
                "target_node_id": fix.target_node_id,
                "title": fix.title,
                "description": fix.description,
                "estimated_paths_reduced": fix.estimated_paths_reduced,
                "estimated_risk_reduction": min(35, max(8, fix.estimated_paths_reduced * 10)),
                "priority": fix.priority,
            }
        )
    adapted.sort(key=lambda item: item["priority"])
    return adapted


def adapt_ai_report(
    ai_result: Any,
    threat: ThreatIntelligenceResponse,
    security: SecurityExtractionResponse,
    summary_risk: int,
) -> Dict[str, Any]:
    file_candidates = collect_affected_files(security, threat)
    severity = severity_from_score(summary_risk)

    if ai_result is not None:
        report = ai_result.ai_report
        return {
            "threat_title": report.threat_title,
            "severity": normalize_severity(report.severity),
            "executive_summary": report.executive_summary,
            "why_it_matters": report.why_it_matters,
            "affected_files": file_candidates,
            "key_findings": report.key_findings,
            "recommended_fixes": report.recommended_fixes,
            "developer_summary": report.developer_summary,
            "confidence": 0.9 if ai_result.status == "ai_reasoning_completed" else 0.68,
        }

    top_path = threat.attack_paths[0] if threat.attack_paths else None
    return {
        "threat_title": "Security exposure detected in repository graph",
        "severity": normalize_severity(top_path.severity_hint) if top_path else severity,
        "executive_summary": (
            f"The scan identified {len(threat.attack_paths)} attack path(s) and an overall risk score of {summary_risk}."
        ),
        "why_it_matters": "Public endpoints, secrets, and risky dependencies can combine into exploitable attack chains.",
        "affected_files": file_candidates,
        "key_findings": [path.summary for path in threat.attack_paths[:3]] or ["No attack paths were generated."],
        "recommended_fixes": [
            "Rotate exposed secrets and move them to environment variables.",
            "Patch or replace risky dependencies.",
            "Review public endpoints and add authentication where needed.",
        ],
        "developer_summary": "Start with the highest-risk path and fix the bottleneck node that appears in multiple paths.",
        "confidence": 0.65,
    }


def collect_affected_files(
    security: SecurityExtractionResponse,
    threat: ThreatIntelligenceResponse,
) -> List[str]:
    files: List[str] = []
    for secret in security.secrets:
        if secret.file_path:
            files.append(secret.file_path)
    for dep in security.dependencies:
        if dep.risk_status == "risk_candidate":
            files.append(dep.source_file)
    for endpoint in security.endpoints:
        files.append(endpoint.file_path)
    unique = []
    seen = set()
    for path in files:
        if path and path not in seen:
            seen.add(path)
            unique.append(path)
    return unique[:8]


def compute_overall_risk_score(
    attack_paths: List[Dict[str, Any]],
    findings: Dict[str, Any],
    top_risks: List[Dict[str, Any]],
) -> int:
    if attack_paths:
        avg_path = sum(path["risk_score"] for path in attack_paths) / len(attack_paths)
    else:
        avg_path = 0
    pressure = len(findings["secrets"]) * 10 + len(findings["vulnerabilities"]) * 8 + len(findings["endpoints"]) * 4
    top_risk_bonus = max((risk["risk_score"] for risk in top_risks), default=0) * 0.2
    score = round(min(100, avg_path * 0.65 + pressure + top_risk_bonus))
    return max(score, 12 if any(findings.values()) else 0)


def get_node_id(label: str, node: Dict[str, Any]) -> str:
    key_map = {
        "Repository": "repo_id",
        "Developer": "developer_id",
        "Commit": "sha",
        "File": "file_id",
        "Dependency": "dependency_id",
        "VulnerabilityCandidate": "risk_id",
        "Secret": "secret_id",
        "Endpoint": "endpoint_id",
        "RiskyFileTag": "tag_id",
    }
    return str(node[key_map[label]])


def get_node_name(label: str, node: Dict[str, Any]) -> str:
    if label == "Repository":
        return node.get("name", "repository")
    if label == "Developer":
        return node.get("name") or node.get("email") or "developer"
    if label == "Commit":
        sha = node.get("sha", "commit")
        return f"commit {sha[:7]}"
    if label == "File":
        return node.get("path", "file")
    if label == "Dependency":
        return f"{node.get('name', 'dependency')}@{node.get('version', 'unknown')}"
    if label == "VulnerabilityCandidate":
        return node.get("name", "risk candidate")
    if label == "Secret":
        return node.get("type", "secret")
    if label == "Endpoint":
        return f"{node.get('method', '')} {node.get('route', '')}".strip()
    if label == "RiskyFileTag":
        return node.get("risk_type", "risky file")
    return node.get("name", label)


def make_edge_id(rel_type: str, source: str, target: str) -> str:
    return f"{rel_type}::{source}->{target}"


def normalize_severity(severity: str | None) -> str:
    sev = (severity or "medium").lower()
    return sev if sev in SEVERITY_ORDER else "medium"


def max_severity(left: str, right: str) -> str:
    left = normalize_severity(left)
    right = normalize_severity(right)
    return left if SEVERITY_ORDER[left] >= SEVERITY_ORDER[right] else right


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def score_path(severity: str, node_count: int) -> int:
    return min(100, SEVERITY_BASE_SCORE[severity] + max(0, node_count - 2) * 4)
