"""WAF Bypass Handler.

Uses AI to generate evasion headers when requests are blocked (403/429).
"""

from __future__ import annotations

import json
import logging
import random
from typing import Any

from trix.llm.llm import LLM
from trix.llm.config import LLMConfig

logger = logging.getLogger(__name__)


class WAFBypassHandler:
    """Handles WAF blocking by generating bypass headers using AI."""
    
    def __init__(self, config: LLMConfig | None = None):
        self.config = config or LLMConfig()
        self.llm = LLM(config=self.config)
        
    async def generate_bypass_headers(
        self,
        original_url: str,
        original_headers: dict[str, str],
        response_status: int,
        response_body_snippet: str = ""
    ) -> dict[str, str]:
        """Generate headers to bypass WAF.
        
        Args:
            original_url: The blocked URL
            original_headers: Headers used in the blocked request
            response_status: Status code (e.g. 403, 429)
            response_body_snippet: Snippet of the block page
            
        Returns:
            Dictionary of NEW headers to merge/replace.
        """
        try:
            prompt = f"""
            You are a WAF Evasion Specialist.
            
            The following request was blocked by a WAF.
            Target: {original_url}
            Status: {response_status}
            Headers Used: {json.dumps(original_headers, indent=2)}
            Block Response Snippet: {response_body_snippet[:500]}
            
            Task:
            Generate a set of HTTP Headers to bypass this block.
            Consider:
            1. Rotating User-Agent (use a modern, realistic browser UA).
            2. Adding/Modifying X-Forwarded-For, X-Real-IP, Client-IP (use realistic IPs).
            3. modifying Referer/Origin if valid.
            4. Adding specific WAF-bypass headers (e.g. X-Originating-IP: 127.0.0.1).
            
            Return ONLY a raw JSON dict of the new headers.
            Example: {{"User-Agent": "Mozilla/5.0...", "X-Forwarded-For": "127.0.0.1"}}
            """
            
            response = await self.llm.generate([{"role": "user", "content": prompt}])
            content = response.content
            
            # Extract JSON
            import re
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                new_headers = json.loads(match.group(0))
                if isinstance(new_headers, dict):
                    # Sanitize: ensure values are strings
                    return {k: str(v) for k, v in new_headers.items()}
                    
        except Exception as e:
            logger.warning(f"AI WAF Bypass generation failed: {e}")
            
        # Fallback: Simple Rotation if AI fails
        return {
            "User-Agent": f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(100, 130)}.0.0.0 Safari/537.36",
            "X-Forwarded-For": "127.0.0.1"
        }
