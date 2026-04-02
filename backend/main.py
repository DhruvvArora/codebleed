"""
RepoGuard — FastAPI entry point.

Run with:
  uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.repo_ingestion import router as ingestion_router
from routes.security_extraction import router as security_router
from routes.graph_build import router as graph_router
from routes.threat_intelligence import router as threat_router
from routes.ai_reasoning import router as ai_router

# Load .env for GITHUB_TOKEN etc.
load_dotenv()

# ── Logging ────────────────────────────────────────────────────────
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s | %(levelname)-7s | %(name)s — %(message)s",
)

# ── App ────────────────────────────────────────────────────────────
app = FastAPI(
    title=os.getenv("APP_NAME", "RepoGuard API"),
    version="0.1.0",
    description=(
        "AI-powered cybersecurity threat intelligence for "
        "AI-assisted / vibe-coded repositories."
    ),
)

# CORS — use ALLOWED_ORIGINS from .env
origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ─────────────────────────────────────────────────────────
app.include_router(ingestion_router)
app.include_router(security_router)
app.include_router(graph_router)
app.include_router(threat_router)
app.include_router(ai_router)


@app.get("/health", tags=["System"])
async def health_check():
    """Simple liveness probe."""
    return {
        "status": "ok",
        "service": "repoguard",
        "github_token_set": bool(os.getenv("GITHUB_TOKEN")),
    }
