"""
RepoGuard — Core Graph Models / Constants.

Central definitions for allowed node labels and relationship types.
"""

# Node Labels
LABEL_REPOSITORY = "Repository"
LABEL_DEVELOPER = "Developer"
LABEL_COMMIT = "Commit"
LABEL_FILE = "File"
LABEL_DEPENDENCY = "Dependency"
LABEL_VULNERABILITY_CANDIDATE = "VulnerabilityCandidate"
LABEL_SECRET = "Secret"
LABEL_ENDPOINT = "Endpoint"
LABEL_RISKY_FILE_TAG = "RiskyFileTag"

# Relationship Types
REL_PUSHED = "PUSHED"
REL_IN_REPO = "IN_REPO"
REL_MODIFIED = "MODIFIED"
REL_BELONGS_TO = "BELONGS_TO"
REL_IMPORTS = "IMPORTS"
REL_HAS_RISK = "HAS_RISK"
REL_CONTAINS_SECRET = "CONTAINS_SECRET"
REL_EXPOSES = "EXPOSES"
REL_TAGGED_AS = "TAGGED_AS"

# Optional explicit commit introduction relationships
REL_INTRODUCES_SECRET = "INTRODUCES_SECRET"
REL_INTRODUCES_ENDPOINT = "INTRODUCES_ENDPOINT"
REL_INTRODUCES_DEP_RISK = "INTRODUCES_DEP_RISK"
