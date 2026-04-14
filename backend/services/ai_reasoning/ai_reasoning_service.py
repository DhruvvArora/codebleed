"""
CodeBleed — AI Reasoning Service.

Orchestrates the full AI reasoning flow:
1. Simplify intelligence (explanations, rankings)
2. Build prompts
3. Call OpenAI GPT-4o-mini
4. Parse & fallback
"""

import logging
from schemas.ai_reasoning import AIReasoningRequest, AIReasoningResponse, AIReport
from services.ai_reasoning.explanation_service import summarize_complex_paths
from services.ai_reasoning.prioritization_service import rank_fix_candidates, format_candidates_for_ai
from services.ai_reasoning.prompt_builder import build_ai_prompts
from services.ai_reasoning.response_parser import parse_ai_json_response, validate_and_clean_report_data
from integrations.openai_client import OpenAIClient

logger = logging.getLogger(__name__)


def perform_ai_reasoning(request: AIReasoningRequest) -> AIReasoningResponse:
    logger.info("Starting AI Reasoning for repo: %s", request.repository.get("url"))

    path_summary = summarize_complex_paths(request.threat_intelligence.attack_paths)
    fix_summary = format_candidates_for_ai(request.threat_intelligence.fix_candidates)

    prompts = build_ai_prompts(request, path_summary, fix_summary)

    client = OpenAIClient()
    raw_ai_output = client.generate_completion(
        system_prompt=prompts["system_prompt"],
        user_prompt=prompts["user_prompt"],
    )

    ai_data = parse_ai_json_response(raw_ai_output)

    if ai_data:
        cleaned_data = validate_and_clean_report_data(ai_data)
        ai_report = AIReport(**cleaned_data)
        status_note = "ai_reasoning_completed"
    else:
        logger.warning("AI reasoning failed or unavailable — falling back to deterministic report.")
        ai_report = generate_deterministic_fallback(request, path_summary)
        status_note = "deterministic_fallback_reasoning"

    summary = {
        "used_attack_paths": len(request.threat_intelligence.attack_paths),
        "used_fix_candidates": len(request.threat_intelligence.fix_candidates),
        "report_style": request.report_style,
    }

    return AIReasoningResponse(
        repository=request.repository,
        ai_report=ai_report,
        summary=summary,
        status=status_note,
    )


def generate_deterministic_fallback(request: AIReasoningRequest, path_summary: str) -> AIReport:
    """Basic report using technical facts when AI is unavailable."""
    top_path = request.threat_intelligence.attack_paths[0] if request.threat_intelligence.attack_paths else None

    severity = top_path.severity_hint if top_path else "medium"
    title = f"Security Vulnerability: {severity.upper()} severity path detected"

    finding = "Attack path identified by graph traversal analyzer."
    if top_path:
        finding = f"Confirmed path from {top_path.entry_node_id} to {top_path.target_node_id}."

    return AIReport(
        threat_title=title,
        severity=severity,
        executive_summary="Graph-based threat analysis identified critical security paths. AI summary unavailable — showing deterministic report.",
        why_it_matters=f"Unresolved security paths of {severity} severity increase the repository's attack surface.",
        affected_assets=[p.target_node_id for p in request.threat_intelligence.attack_paths[:3]],
        key_findings=[finding],
        recommended_fixes=["Rotate exposed secrets", "Lock down endpoints", "Patch vulnerable dependencies"],
        developer_summary="Prioritize fixing paths linked to public endpoints.",
        confidence_note="DETERMINISTIC_FALLBACK",
    )
