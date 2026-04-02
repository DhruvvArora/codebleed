"""
RepoGuard — Security Extraction Orchestrator.

Takes Component 1's IngestionResponse and runs all detectors
to produce the Component 2 SecurityExtractionResponse.
"""

from __future__ import annotations
import logging
from schemas.repo_ingestion import IngestionResponse
from schemas.security_extraction import SecurityExtractionResponse, SecuritySummary
from services.security_extraction.secret_detector import detect_secrets
from services.security_extraction.dependency_risk_detector import detect_dependency_risks
from services.security_extraction.endpoint_detector import detect_endpoints
from services.security_extraction.risky_file_tagger import tag_risky_files

logger = logging.getLogger(__name__)


def extract_security_findings(ingestion_data: IngestionResponse) -> SecurityExtractionResponse:
    logger.info("Starting security extraction for repo: %s", ingestion_data.repository.name)

    # 1. Detect Secrets
    secrets = detect_secrets(ingestion_data)
    
    # 2. Extract Dependency Risks
    dependencies = detect_dependency_risks(ingestion_data.dependency_files)
    
    # 3. Detect Endpoints
    endpoints = detect_endpoints(ingestion_data)
    
    # 4. Tag Risky Files
    risky_files = tag_risky_files(ingestion_data)
    
    # Build Summary
    summary = SecuritySummary(
        secrets_found=len(secrets),
        dependencies_extracted=len(dependencies),
        dependency_risk_candidates=len([d for d in dependencies if d.risk_status == "risk_candidate"]),
        endpoints_found=len(endpoints),
        risky_files_tagged=len(risky_files)
    )

    logger.info("Security extraction complete for %s. Found %d secrets, %d dependencies, %d endpoints, %d risky files.", 
                ingestion_data.repository.name, len(secrets), len(dependencies), len(endpoints), len(risky_files))

    return SecurityExtractionResponse(
        repository=ingestion_data.repository,
        secrets=secrets,
        dependencies=dependencies,
        endpoints=endpoints,
        risky_files=risky_files,
        summary=summary
    )
