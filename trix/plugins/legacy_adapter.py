"""Legacy Plugin Adapter - Bridges old plugins with the AI-Native Controller.

This allows legacy plugins (BasePlugin) to be loaded and called by the
ScanController without breaking the interface.
"""

from typing import Any
from trix.plugins.vulns import BaseVulnPlugin, PayloadContext, PayloadSpec
from trix.models.finding import VulnFinding
from trix.models.judgment import JudgmentResult

class LegacyPluginAdapter(BaseVulnPlugin):
    """Adapter to make legacy plugins compatible with AI-Native ScanController."""
    
    def __init__(self, name: str = "legacy_plugin", vuln_type: str = "generic"):
        self.name = name
        self.vuln_type = vuln_type
        self.enabled = True
        
    def generate_payloads(self, context: PayloadContext) -> list[PayloadSpec]:
        """Simple passthrough that doesn't generate actual mutations.
        
        This allows legacy plugins to fulfill the BaseVulnPlugin interface
        while still relying on their internal logic if manually triggered.
        """
        return [PayloadSpec(
            payload="", 
            description="Legacy passthrough payload",
            expected_behavior="Legacy tool internal detection"
        )]
        
    def get_judgment_context(self, payload: PayloadSpec) -> dict[str, Any]:
        """Legacy plugins don't provide judgment hints for LLM."""
        return {}
        
    def process_judgment(
        self,
        payload: PayloadSpec,
        result: JudgmentResult,
        raw_request: str,
        raw_response: str,
        target: str,
    ) -> VulnFinding | None:
        """Directly trusts the judgment output or formats legacy results."""
        if not result.is_vulnerable:
            return None
            
        return VulnFinding(
            target=target,
            vuln_type=self.vuln_type,
            payload=payload.payload or "Legacy Plugin Execution",
            raw_request=raw_request,
            raw_response=raw_response,
            llm_reasoning=result.reasoning,
            confidence_score=result.confidence_score,
            confidence_level=result.confidence_level,
            risk_level=result.risk_level,
            evidence=result.evidence,
            plugin_name=self.name,
        )
