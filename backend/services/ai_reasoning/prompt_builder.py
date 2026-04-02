"""
RepoGuard — AI Prompt Builder.

Constructs structured prompts for the RocketRide model based on graph data.
"""

import os
from typing import Dict, Any
from schemas.ai_reasoning import AIReasoningRequest

SYSTEM_PROMPT = """You are an expert Cybersecurity Security Analyst specializing in Graph-based Threat Intelligence.
Your role is to reason over structured evidence from a code repository graph to explain threats and prioritize fixes.
You will be provided with:
1. Repository Context
2. Attack Path evidence (Endpoint -> Vulnerability -> Secret)
3. Top Risk entities (Dependencies, Files)
4. Fix Candidates with estimated impact.

INSTRUCTIONS:
- Reason only from the provided graph intelligence.
- Do not invent facts or external context.
- Be concise, actionable, and professionally skeptical.
- Prioritize high-impact remediations that break attack paths.

OUTPUT FORMAT:
Return your response ONLY as a JSON object with the following fields:
{
  "threat_title": "string",
  "severity": "critical|high|medium|low",
  "executive_summary": "string (2-3 sentences)",
  "why_it_matters": "string (impact explanation)",
  "affected_assets": ["list of strings"],
  "key_findings": ["list of strings"],
  "recommended_fixes": ["list of strings in priority order"],
  "developer_summary": "string (concise first-action advice)"
}
"""

def build_ai_prompts(request: AIReasoningRequest, path_summary: str, fix_summary: str) -> Dict[str, str]:
    """Generates the system and user prompts."""
    
    user_prompt = f"""
REPO NAME: {request.repository.get('name', 'Unknown')}
REPO URL: {request.repository.get('url', 'Unknown')}

GRAPH THREAT INTELLIGENCE SUMMARY:
Attack Paths Found: {request.threat_intelligence.summary.attack_paths_found}
Top Risks Found: {request.threat_intelligence.summary.top_dependency_risks} dependencies, {request.threat_intelligence.summary.top_file_risks} files.

EVIDENCE - ATTACK PATHS:
{path_summary}

EVIDENCE - TOP FIX CANDIDATES:
{fix_summary}

REPORT STYLE REQUIRED: {request.report_style}
MAX RECOMMENDATIONS: {request.max_recommendations}

Please generate the security report according to the JSON format specified in the system prompt.
"""
    return {
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt": user_prompt
    }
