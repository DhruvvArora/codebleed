"""
RepoGuard — RocketRide AI API Client.

Wraps all external AI reasoning calls. Uses ROCKETRIDE_* environment variables.
"""

from __future__ import annotations
import os
import logging
import httpx
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class RocketRideClient:
    """Thin wrapper for RocketRide AI model interaction."""
    
    def __init__(self):
        self.api_key = os.getenv("ROCKETRIDE_API_KEY")
        self.base_url = os.getenv("ROCKETRIDE_API_BASE_URL", "https://api.rocketride.ai/v1")
        self.model = os.getenv("ROCKETRIDE_MODEL", "rocketride-3-pro")
        
        if not self.api_key:
            logger.warning("ROCKETRIDE_API_KEY not found in environment.")

    def generate_completion(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Call the RocketRide completion API (Sync)."""
        if not self.api_key:
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2, # Lower temperature for reasoning consistency
            "response_format": {"type": "json_object"}
        }

        try:
            # We use a 30s timeout for demo stability
            with httpx.Client(timeout=30.0) as client:
                response = client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.error(f"RocketRide AI API call failed: {exc}")
            return None
