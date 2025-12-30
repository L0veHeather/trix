"""LLM-based Parameter Guesser.

Uses AI to infer potential input parameters for a given endpoint based on
URL structure, HTTP method, and page content (HTML/JS).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from trix.llm.llm import LLM
from trix.llm.config import LLMConfig

logger = logging.getLogger(__name__)


class LLMParamGuesser:
    """Uses LLM to guess parameters for semantic vulnerability testing."""
    
    def __init__(self, config: LLMConfig | None = None):
        self.config = config or LLMConfig()
        self.llm = LLM(config=self.config)
        
    async def guess_parameters(
        self,
        url: str,
        method: str,
        page_content: str = "",
        limit: int = 15
    ) -> list[str]:
        """Guess potential parameters for the endpoint.
        
        Args:
            url: Target URL
            method: HTTP Method (GET, POST, etc.)
            page_content: Optional HTML/JS content from the page
            limit: Max number of parameters to return
            
        Returns:
            List of parameter names (e.g. ['id', 'user_id', 'query'])
        """
        try:
            # Truncate content to avoid token limits
            content_snippet = page_content[:2000] if page_content else "No content available"
            
            prompt = f"""
            You are a Parameter Discovery Agent. 
            Analyze the following HTTP Endpoint and Context to guess valid request parameters.
            
            Target: {method} {url}
            Context Snippet:
            {content_snippet}
            
            Task:
            1. Infer parameters based on the URL path (e.g. /users/profile -> user_id, profile_id).
            2. Infer parameters based on common variable naming conventions for this type of functionality.
            3. Infer parameters from any HTML forms or JS variables visible in the context.
            4. Include common debug parameters if appropriate (debug, test, admin).
            
            Return ONLY a raw JSON list of strings. Max {limit} items.
            Example: ["id", "uid", "user", "q", "search"]
            """
            
            response = await self.llm.generate([{"role": "user", "content": prompt}])
            content = response.content
            
            # Simple JSON extraction
            # In a real implementation we would use a robust parser or tool calling
            import re
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                params = json.loads(match.group(0))
                return [p for p in params if isinstance(p, str)][:limit]
                
        except Exception as e:
            logger.warning(f"LLM Parameter Guessing failed: {e}")
            
        return []
