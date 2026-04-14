"""
CodeBleed — OpenAI API client for AI reasoning.

Replaces RocketRide. Calls GPT-4o-mini directly via httpx.
Set OPENAI_API_KEY in your environment.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIClient:
    """Thin wrapper for OpenAI chat completions."""

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("OPENAI_MODEL", DEFAULT_MODEL)

        if not self.api_key:
            logger.warning("OPENAI_API_KEY not set — AI reasoning will fall back to deterministic mode.")

    def generate_completion(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Call GPT-4o-mini and return the raw text response."""
        if not self.api_key:
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(OPENAI_API_URL, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.error("OpenAI API call failed: %s", exc)
            return None
