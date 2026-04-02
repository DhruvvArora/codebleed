"""
RepoGuard — AI Reasoning Service (Orchestrator).

Orchestrates the full AI reasoning flow:
1. Simplify intelligence (explanations, rankings)
2. Build Prompts
3. Call RocketRide AI
4. Parse & Fallback
"""

import logging
from typing import Dict, Any
from schemas.ai_reasoning import AIReasoningRequest, AIReasoningResponse, AIReport
from services.ai_reasoning.explanation_service import summarize_complex_paths
from services.ai_reasoning.prioritization_service import rank_fix_candidates, format_candidates_for_ai
from services.ai_reasoning.prompt_builder import build_ai_prompts
from services.ai_reasoning.response_parser import parse_ai_json_response, validate_and_clean_report_data
from integrations.rocketride_client import RocketRideClient

logger = logging.getLogger(__name__)

def perform_ai_reasoning(request: AIReasoningRequest) -> AIReasoningResponse:
    logger.info("Starting AI Reasoning Layer for Repo: %s", request.repository.get("url"))

    # 1. Prepare deterministic input summaries
    path_summary = summarize_complex_paths(request.threat_intelligence.attack_paths)
    fix_summary = format_candidates_for_ai(request.threat_intelligence.fix_candidates)

    # 2. Build AI Prompts
    prompts = build_ai_prompts(request, path_summary, fix_summary)

    # 3. Call RocketRide AI Client
    client = RocketRideClient()
    raw_ai_output = client.generate_completion(
        system_prompt=prompts["system_prompt"],
        user_prompt=prompts["user_prompt"]
    )

    # 4. Parse & Process
    ai_data = parse_ai_json_response(raw_ai_output)
    
    if ai_data:
        # Success via AI
        cleaned_data = validate_and_clean_report_data(ai_data)
        ai_report = AIReport(**cleaned_data)
        status_note = "ai_reasoning_completed"
    else:
        # FALLBACK: Deterministic Reasoning if AI Fails
        logger.warning("Falling back to deterministic reasoning.")
        ai_report = generate_deterministic_fallback(request, path_summary)
        status_note = "deterministic_fallback_reasoning"

    summary = {
        "used_attack_paths": len(request.threat_intelligence.attack_paths),
        "used_fix_candidates": len(request.threat_intelligence.fix_candidates),
        "report_style": request.report_style
    }

    return AIReasoningResponse(
        repository=request.repository,
        ai_report=ai_report,
        summary=summary,
        status=status_note
    )

def generate_deterministic_fallback(request: AIReasoningRequest, path_summary: str) -> AIReport:
    """Creates a basic report using technical facts if the AI is unavailable."""
    top_path = request.threat_intelligence.attack_paths[0] if request.threat_intelligence.attack_paths else None
    
    severity = top_path.severity_hint if top_path else "medium"
    title = f"Security Vulnerability: {severity.upper()} severity path detected"
    
    finding = "Attack path identified by graph traversal analyzer."
    if top_path:
        finding = f"Confirmed path from {top_path.entry_node_id} to {top_path.target_node_id}."
        
    return AIReport(
        threat_title=title,
        severity=severity,
        executive_summary="Graph-based threat analysis identified critical security paths. AI-generated summary was unavailable, falling back to technical data.",
        why_it_matters=f"Unresolved security paths of {severity} severity increase the repository's attack surface and exposure.",
        affected_assets=[p.target_node_id for p in request.threat_intelligence.attack_paths[:3]],
        key_findings=[finding],
        recommended_fixes=["Rotate exposed secrets", "Lock down endpoints", "Patch vulnerable dependencies"],
        developer_summary="Prioritize fixing paths linked to public endpoints.",
        confidence_note="REPORT_GENERATED_BY_DETERMINISTIC_FALLBACK"
    )
