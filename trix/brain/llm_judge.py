"""LLM Judge - Abstract base class for all LLM-based vulnerability judgment.

This replaces traditional regex/keyword matching with LLM-powered analysis.
All HTTP response security judgments flow through this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from trix.models.finding import VulnFinding
from trix.models.judgment import JudgmentRequest, JudgmentResult


class LLMJudge(ABC):
    """Abstract base class for LLM-based vulnerability judgment.
    
    Design principles:
    1. This is the ONLY entry point for all vulnerability judgments
    2. Replaces regex/keyword matching with LLM analysis
    3. Provides consistent interface for different LLM backends
    4. Supports batch processing to optimize API costs
    
    Usage:
        judge = OpenAIJudge(model="gpt-4o-mini")
        result = await judge.judge(request)
        if result.is_vulnerable:
            print(f"Found: {result.reasoning}")
    """
    
    @abstractmethod
    async def judge(self, request: JudgmentRequest) -> JudgmentResult:
        """Execute LLM judgment on a single request.
        
        This is the core method that analyzes HTTP responses for vulnerabilities.
        
        Args:
            request: JudgmentRequest containing target, payload, request/response
            
        Returns:
            JudgmentResult with is_vulnerable, reasoning, confidence, evidence
        """
        pass
    
    @abstractmethod
    async def batch_judge(
        self, 
        requests: list[JudgmentRequest]
    ) -> list[JudgmentResult]:
        """Batch judgment for multiple requests.
        
        Optimizes LLM API calls by combining similar requests.
        Useful for reducing token costs when testing multiple payloads.
        
        Args:
            requests: List of JudgmentRequest objects
            
        Returns:
            List of JudgmentResult in same order as requests
        """
        pass
    
    @abstractmethod
    async def analyze_false_positive(
        self,
        finding: VulnFinding,
        additional_context: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Analyze whether a finding is a false positive.
        
        Called after initial detection to double-check findings.
        
        Args:
            finding: The vulnerability finding to analyze
            additional_context: Extra context for analysis
            
        Returns:
            Tuple of (is_false_positive, reasoning)
        """
        pass
    
    @abstractmethod
    async def suggest_mutations(
        self,
        vuln_type: str,
        failed_payloads: list[str],
        response_patterns: list[str],
    ) -> list[str]:
        """Suggest payload mutations when current payloads fail.
        
        When existing payloads don't trigger vulnerabilities,
        ask LLM to suggest new mutation directions based on
        observed response patterns.
        
        Args:
            vuln_type: Vulnerability type (sqli, xss, etc.)
            failed_payloads: List of payloads that didn't work
            response_patterns: Observed patterns in responses
            
        Returns:
            List of new payload suggestions
        """
        pass
    
    @abstractmethod
    async def generate_verification_task(
        self,
        request: "JudgmentRequest",
        result: "JudgmentResult",
        task_id: str,
        parent_task_id: str | None = None,
        depth: int = 0,
    ) -> "VerificationTask | None":
        """Generate a follow-up verification task when confidence is uncertain.
        
        Called when JudgmentResult.confidence_score is in the uncertain zone
        (typically 50-80%). The AI generates a new verification payload to
        confirm or reject the potential vulnerability.
        
        Args:
            request: Original JudgmentRequest
            result: JudgmentResult with uncertain confidence
            task_id: Unique ID for the new verification task
            parent_task_id: ID of the original/parent task
            depth: Current recursion depth (for loop prevention)
            
        Returns:
            VerificationTask with new payload and instructions,
            or None if maximum depth reached or no useful verification possible
        """
        pass
    
    # === Helper methods ===
    
    def get_vuln_prompt(self, vuln_type: str) -> str:
        """Get vulnerability-specific prompt from knowledge base.
        
        Loads from trix/prompts/vulnerabilities/{vuln_type}.jinja
        
        Args:
            vuln_type: Vulnerability type (sqli, xss, etc.)
            
        Returns:
            Prompt content for this vulnerability type
        """
        from pathlib import Path
        
        prompts_dir = Path(__file__).parent.parent / "prompts" / "vulnerabilities"
        prompt_file = prompts_dir / f"{vuln_type}.jinja"
        
        if prompt_file.exists():
            return prompt_file.read_text()
        
        return ""
    
    def build_system_prompt(self, vuln_type: str | None = None) -> str:
        """Build the system prompt for LLM.
        
        Combines base security analysis prompt with
        vulnerability-specific knowledge if provided.
        """
        base_prompt = """You are an expert security analyst specializing in vulnerability detection.

Your task is to analyze HTTP request/response pairs and determine if they indicate security vulnerabilities.

## Analysis Guidelines:

1. **Focus on Evidence**: Look for concrete indicators of vulnerability, not assumptions
2. **Consider Context**: The payload, expected behavior, and response together
3. **Avoid False Positives**: Be conservative - only confirm when evidence is strong
4. **Explain Reasoning**: Clearly articulate why you believe a vulnerability exists or not
5. **PoC Generation**: For every confirmed vulnerability, you MUST provide the **Raw HTTP Request** (including headers and payload)

## Response Format:

You must respond with a JSON object containing:
- is_vulnerable: boolean
- confidence_score: float (0.0-1.0)
- risk_level: "critical" | "high" | "medium" | "low" | "info"
- reasoning: string explaining your analysis
- evidence: array of specific evidence points
- http_poc: string (raw HTTP request format, required if vulnerable)
- false_positive_reasons: array of reasons if not vulnerable
- mutation_suggestions: array of suggested payload variations if needs more testing
"""
        
        if vuln_type:
            vuln_prompt = self.get_vuln_prompt(vuln_type)
            if vuln_prompt:
                base_prompt += f"\n\n## Vulnerability-Specific Knowledge:\n\n{vuln_prompt}"
        
        return base_prompt
