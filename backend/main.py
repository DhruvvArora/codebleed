"""
CodeBleed — FastAPI entry point.

Run with:
  uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.scan import router as scan_router

load_dotenv()

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s | %(levelname)-7s | %(name)s — %(message)s",
)

app = FastAPI(
    title="CodeBleed API",
    version="0.1.0",
    description=(
        "AI-powered cybersecurity threat intelligence for "
        "AI-assisted / vibe-coded repositories."
    ),
)

origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)


@app.get("/health", tags=["System"])
async def health_check():
    """Simple liveness probe."""
    return {
        "status": "ok",
        "service": "codebleed",
        "github_token_set": bool(os.getenv("GITHUB_TOKEN")),
    }
