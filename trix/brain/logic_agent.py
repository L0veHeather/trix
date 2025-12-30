"""Business Logic Agent for IDOR and Privilege Escalation Detection.

Uses LLM to analyze API structure and generate targeted test payloads
for business logic vulnerabilities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
from enum import Enum

from trix.core.knowledge_graph import KnowledgeGraph, get_knowledge_graph, ResourceType

logger = logging.getLogger(__name__)


class LogicVulnType(str, Enum):
    """Types of business logic vulnerabilities."""
    
    IDOR = "idor"                           # Insecure Direct Object Reference
    HORIZONTAL_PRIV_ESC = "horizontal_priv_esc"  # Access other user's data
    VERTICAL_PRIV_ESC = "vertical_priv_esc"      # Elevate to admin
    MASS_ASSIGNMENT = "mass_assignment"          # Modify protected fields
    RATE_LIMIT_BYPASS = "rate_limit_bypass"      # Bypass rate limiting
    PRICE_MANIPULATION = "price_manipulation"    # Modify prices/amounts


@dataclass
class IntendedAction:
    """An action the AI intends to perform for testing."""
    
    action_id: str
    vuln_type: LogicVulnType
    description: str
    
    # HTTP request details
    method: str
    path: str
    original_path: str
    
    # Payload info
    original_value: str
    modified_value: str
    parameter: str | None = None
    
    # Risk and priority
    risk_score: int = 50
    priority: int = 50
    
    # Evidence expectation
    expected_success_indicators: list[str] = field(default_factory=list)
    expected_failure_indicators: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "vuln_type": self.vuln_type.value,
            "description": self.description,
            "method": self.method,
            "path": self.path,
            "original_path": self.original_path,
            "original_value": self.original_value,
            "modified_value": self.modified_value,
            "risk_score": self.risk_score,
        }


# IDOR analysis prompt template
IDOR_ANALYSIS_PROMPT = """You are a security researcher analyzing API endpoints for IDOR vulnerabilities.

## Discovered API Endpoints
{endpoints_json}

## Known Resource IDs
{resource_ids_json}

## Relationships
{relationships_json}

## Task
Analyze these endpoints and identify potential IDOR (Insecure Direct Object Reference) vulnerabilities.

For each high-risk endpoint:
1. Explain why it's vulnerable
2. Suggest a specific test case (changing which ID to what)
3. What response would confirm the vulnerability

## Output Format
Return a JSON array of test cases:
```json
[
  {{
    "endpoint": "/api/users/123/orders/456",
    "vuln_type": "horizontal_idor",
    "reason": "User can access other users' orders by changing user_id",
    "test": {{
      "original_id": "123",
      "modified_id": "124",
      "parameter": "user_id"
    }},
    "success_indicators": ["200 status", "order data returned", "different user's email"],
    "risk_score": 85
  }}
]
```

Focus on:
1. User-owned resources (orders, files, messages)
2. Numeric/sequential IDs (easy to guess)
3. Nested routes (cross-user access)
4. Admin endpoints accessible without admin auth
"""


class BusinessLogicAgent:
    """AI agent for detecting business logic vulnerabilities.
    
    Triggered after ENUMERATION phase when enough URLs are collected.
    Uses LLM to reason about API structure and generate targeted tests.
    
    Example:
        agent = BusinessLogicAgent()
        agent.feed_endpoints(["/api/users/123/orders", "/api/admin/config"])
        
        async for action in agent.analyze():
            print(f"Test: {action.description}")
    """
    
    def __init__(
        self,
        knowledge_graph: KnowledgeGraph | None = None,
        llm_client: Any = None,
    ):
        self._graph = knowledge_graph or get_knowledge_graph()
        self._llm = llm_client
        self._analyzed = False
        
        # Stats
        self.stats = {
            "endpoints_analyzed": 0,
            "idor_tests_generated": 0,
            "vulns_confirmed": 0,
        }
    
    def feed_endpoint(self, path: str, method: str = "GET") -> None:
        """Feed a discovered endpoint to the knowledge graph."""
        self._graph.add_endpoint(path, method)
        self._analyzed = False
    
    def feed_endpoints(self, endpoints: list[dict[str, str]]) -> None:
        """Feed multiple endpoints at once.
        
        Args:
            endpoints: List of {"path": ..., "method": ...}
        """
        for ep in endpoints:
            self._graph.add_endpoint(
                ep.get("path", ep.get("url", "")),
                ep.get("method", "GET")
            )
        self._analyzed = False
        logger.info(f"[LogicAgent] Fed {len(endpoints)} endpoints to knowledge graph")
    
    async def analyze(self) -> AsyncIterator[IntendedAction]:
        """Analyze API structure and generate test actions.
        
        Yields IntendedAction objects for each identified test.
        """
        import json
        import uuid
        
        # First, use rule-based analysis
        logger.info("[LogicAgent] Starting rule-based IDOR analysis...")
        
        test_cases = self._graph.generate_idor_test_cases()
        self.stats["endpoints_analyzed"] = len(self._graph.get_all_endpoints())
        
        for tc in test_cases:
            action = IntendedAction(
                action_id=str(uuid.uuid4())[:8],
                vuln_type=(LogicVulnType.HORIZONTAL_PRIV_ESC 
                          if tc["test_type"] == "horizontal_privilege_escalation"
                          else LogicVulnType.IDOR),
                description=f"IDOR test: Change {tc['resource_type']} ID from {tc['original_id']} to {tc['modified_id']}",
                method=tc["method"],
                path=tc["modified_path"],
                original_path=tc["original_path"],
                original_value=tc["original_id"],
                modified_value=tc["modified_id"],
                parameter=f"{tc['resource_type']}_id",
                risk_score=tc["risk_score"],
                priority=100 - tc["risk_score"],  # Higher risk = higher priority (lower number)
                expected_success_indicators=["200", "data returned", "unauthorized data"],
                expected_failure_indicators=["403", "401", "not found", "access denied"],
            )
            self.stats["idor_tests_generated"] += 1
            yield action
        
        # Then, use LLM for deeper analysis if available
        if self._llm is not None and len(self._graph.get_all_endpoints()) > 0:
            logger.info("[LogicAgent] Starting LLM-powered analysis...")
            async for action in self._analyze_with_llm():
                yield action
        
        self._analyzed = True
    
    async def _analyze_with_llm(self) -> AsyncIterator[IntendedAction]:
        """Use LLM to analyze API structure for vulnerabilities."""
        import json
        import uuid
        
        # Prepare context
        graph_data = self._graph.to_dict()
        
        prompt = IDOR_ANALYSIS_PROMPT.format(
            endpoints_json=json.dumps(graph_data["endpoints"][:30], indent=2),  # Limit
            resource_ids_json=json.dumps(graph_data["resource_ids"], indent=2),
            relationships_json=json.dumps(graph_data["relationships"][:20], indent=2),
        )
        
        try:
            # Lazy-load LLM if needed
            if self._llm is None:
                from trix.llm.llm import LLM
                from trix.llm.config import LLMConfig
                self._llm = LLM(LLMConfig(), agent_name=None)
            
            response = await self._llm.generate(
                conversation_history=[{"role": "user", "content": prompt}]
            )
            
            # Parse response
            content = response.content.strip()
            start = content.find('[')
            end = content.rfind(']') + 1
            
            if start != -1 and end > start:
                json_str = content[start:end]
                test_cases = json.loads(json_str)
                
                for tc in test_cases:
                    if not isinstance(tc, dict):
                        continue
                    
                    test = tc.get("test", {})
                    action = IntendedAction(
                        action_id=str(uuid.uuid4())[:8],
                        vuln_type=LogicVulnType.IDOR,
                        description=tc.get("reason", "LLM-identified IDOR risk"),
                        method="GET",  # Default
                        path=tc.get("endpoint", "").replace(
                            test.get("original_id", ""),
                            test.get("modified_id", "")
                        ),
                        original_path=tc.get("endpoint", ""),
                        original_value=test.get("original_id", ""),
                        modified_value=test.get("modified_id", ""),
                        parameter=test.get("parameter"),
                        risk_score=tc.get("risk_score", 50),
                        expected_success_indicators=tc.get("success_indicators", []),
                    )
                    self.stats["idor_tests_generated"] += 1
                    yield action
                    
        except Exception as e:
            logger.warning(f"[LogicAgent] LLM analysis failed: {e}")
    
    def get_high_risk_endpoints(self) -> list[dict[str, Any]]:
        """Get high-risk endpoints from knowledge graph."""
        return [ep.to_dict() for ep in self._graph.get_high_risk_endpoints()]
    
    def get_stats(self) -> dict[str, int]:
        """Get analysis statistics."""
        return {
            **self.stats,
            "total_endpoints": len(self._graph.get_all_endpoints()),
            "high_risk_endpoints": len(self._graph.get_high_risk_endpoints()),
        }


# Global instance
_logic_agent: BusinessLogicAgent | None = None


def get_business_logic_agent() -> BusinessLogicAgent:
    """Get the global business logic agent."""
    global _logic_agent
    if _logic_agent is None:
        _logic_agent = BusinessLogicAgent()
    return _logic_agent
