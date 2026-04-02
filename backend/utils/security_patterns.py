"""
RepoGuard — Reusable regex and keyword patterns for security extraction.
"""

import re

# ── Secret Patterns ─────────────────────────────────────────────

SECRET_PATTERNS = {
    # e.g. AKIAIOSFODNN7EXAMPLE
    "aws_access_key": re.compile(r"(?i)\b(AKIA[0-9A-Z]{16})\b"),
    # GitHub fine-grained or classic tokens
    "github_token": re.compile(r"(?i)\b(gh[p|u|s|r|o]_[a-zA-Z0-9]{36})\b"),
    # OpenAI sk- keys
    "openai_key": re.compile(r"(?i)\b(sk-[a-zA-Z0-9]{32,})\b"),
    # Generic assignments (e.g. API_KEY="xyz" or password='123')
    "generic_key": re.compile(r"(?i)(api_key|secret|token|password|auth)[\s]*[:=][\s]*['\"]([^'\"]{8,})['\"]"),
}

# ── Endpoint Patterns ──────────────────────────────────────────

ENDPOINT_PATTERNS = {
    "express_get": re.compile(r"app\.get\(['\"]([^'\"]+)['\"]"),
    "express_post": re.compile(r"app\.post\(['\"]([^'\"]+)['\"]"),
    "express_put": re.compile(r"app\.put\(['\"]([^'\"]+)['\"]"),
    "express_delete": re.compile(r"app\.delete\(['\"]([^'\"]+)['\"]"),
    "fastapi_get": re.compile(r"@app\.get\(['\"]([^'\"]+)['\"]"),
    "fastapi_post": re.compile(r"@app\.post\(['\"]([^'\"]+)['\"]"),
    "router_get": re.compile(r"router\.get\(['\"]([^'\"]+)['\"]"),
    "router_post": re.compile(r"router\.post\(['\"]([^'\"]+)['\"]"),
    "flask_route": re.compile(r"@app\.route\(['\"]([^'\"]+)['\"]"),
}

ENDPOINT_PATH_HINTS = ["api", "routes", "controllers", "pages/api", "app/api"]

# ── Risky File Heuristics ──────────────────────────────────────

RISKY_FILE_KEYWORDS = {
    "env_sensitive": [".env", "environment", "dotenv"],
    "config_sensitive": ["config", "settings", "setup", "secrets"],
    "auth_sensitive": ["auth", "login", "creds", "credentials", "oauth", "jwt"],
    "admin_sensitive": ["admin", "dashboard", "sudo", "superuser"],
    "db_sensitive": ["database", "db", "mysql", "postgres", "mongo", "redis"],
    "payment_sensitive": ["payment", "billing", "stripe", "checkout", "paypal"],
}
