"""
RepoGuard — Dependency Risk Detector.

Parses dependency files (package.json, requirements.txt, etc.) from Component 1
and heuristically labels dependencies. MVP only tags names/versions; no full CVE lookup.
"""

from __future__ import annotations
import json
import re
import uuid
from schemas.repo_ingestion import DependencyFile
from schemas.security_extraction import DependencyFinding


def extract_package_json(dep_file: DependencyFile) -> list[DependencyFinding]:
    findings = []
    try:
        data = json.loads(dep_file.content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}
        
        for name, version in all_deps.items():
            findings.append(
                DependencyFinding(
                    id=f"dep_{uuid.uuid4().hex[:8]}",
                    name=name,
                    version=version,
                    source_file=dep_file.path,
                    risk_status="risk_candidate",
                    reason="Not verified against CVE database; flagged heuristically"
                )
            )
    except Exception:
        pass
    return findings


def extract_requirements_txt(dep_file: DependencyFile) -> list[DependencyFinding]:
    findings = []
    lines = dep_file.content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # simple parsing: split at ==, >=, <=, ~>
        parts = re.split(r'[=><~]+', line)
        if len(parts) >= 2:
            name = parts[0].strip()
            version = parts[1].strip()
            findings.append(
                DependencyFinding(
                    id=f"dep_{uuid.uuid4().hex[:8]}",
                    name=name,
                    version=version,
                    source_file=dep_file.path,
                    risk_status="risk_candidate",
                    reason="Not verified against CVE database; flagged heuristically"
                )
            )
    return findings


def detect_dependency_risks(dependency_files: list[DependencyFile]) -> list[DependencyFinding]:
    all_findings = []
    for df in dependency_files:
        if df.type == "package.json":
            all_findings.extend(extract_package_json(df))
        elif df.type == "requirements.txt":
            all_findings.extend(extract_requirements_txt(df))
        # pyproject.toml / others omitted in MVP for hackathon speed
    return all_findings
