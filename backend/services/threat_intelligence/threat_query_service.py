"""
RepoGuard — Threat Query Service (Orchestrator).

Orchestrates all graph threat queries and combines them into one result.
"""

import logging
from typing import Dict
from schemas.threat_intelligence import ThreatIntelligenceRequest, ThreatIntelligenceResponse, IntelligenceSummary
from services.threat_intelligence.attack_path_service import get_attack_paths
from services.threat_intelligence.blast_radius_service import get_top_risks
from services.threat_intelligence.root_cause_service import analyze_root_causes
from services.threat_intelligence.fix_candidate_service import generate_fix_candidates

logger = logging.getLogger(__name__)

def perform_threat_analysis(request: ThreatIntelligenceRequest) -> ThreatIntelligenceResponse:
    repo_url = request.repository_url
    logger.info("Starting graph threat analysis for repo: %s", repo_url)

    # 1. Attack Paths
    attack_paths = get_attack_paths(repo_url, limit=request.max_paths)
    
    # 2. Blast Radius (Top Risks)
    top_risks = get_top_risks(repo_url, limit=request.max_risks)
    
    # 3. Root Causes
    root_causes = analyze_root_causes(repo_url, limit=request.max_risks)
    
    # 4. Fix Candidates
    fix_candidates = []
    if request.include_fix_candidates:
        fix_candidates = generate_fix_candidates(repo_url, limit=request.max_risks)

    summary = IntelligenceSummary(
        attack_paths_found=len(attack_paths),
        top_dependency_risks=len(top_risks.dependencies),
        top_file_risks=len(top_risks.files),
        top_endpoint_risks=len(top_risks.endpoints),
        root_causes_found=len(root_causes),
        fix_candidates_found=len(fix_candidates)
    )

    return ThreatIntelligenceResponse(
        repository={"url": repo_url},
        attack_paths=attack_paths,
        top_risks=top_risks,
        root_causes=root_causes,
        fix_candidates=fix_candidates,
        summary=summary
    )
