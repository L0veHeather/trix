"""IDOR (Insecure Direct Object Reference) Detection Plugin.

Strategy:
1. Single User Mode (Authorization Bypass):
   - Compare Authenticated vs Anonymous access
   - If Anonymous can access protected resource -> Vuln

2. Dual User Mode (Horizontal Privilege Escalation):
   - Config: AuthManager has Victim (A) and Attacker (B)
   - Baseline: A accesses A's resource (e.g., /orders/1001) -> 200 OK
   - Attack: B accesses A's resource (/orders/1001) using B's cookies
   - Judgment: If B gets 200 OK and response similarity > 0.85 -> Vuln
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING
from dataclasses import dataclass

from trix.plugins.vulns import BaseVulnPlugin, PayloadContext, PayloadSpec
from trix.models.finding import VulnFinding
from trix.core.auth_manager import get_auth_manager

if TYPE_CHECKING:
    from trix.core.concurrent_executor import ConcurrentExecutor

logger = logging.getLogger(__name__)


class IDORPlugin(BaseVulnPlugin):
    """Detects Insecure Direct Object Reference vulnerabilities."""
    
    name = "idor_detector"
    vuln_type = "idor"
    description = "Detects IDOR and Authorization Bypass vulnerabilities"
    version = "1.0.0"
    author = "Strix Team"
    
    def generate_payloads(self, context: PayloadContext) -> list[PayloadSpec]:
        """Not used for Logic/IDOR tests managed by ScanEngine."""
        return []
    
    def get_judgment_context(self, payload: PayloadSpec) -> dict[str, Any]:
        return {}

    async def execute_check(
        self,
        executor: "ConcurrentExecutor",
        target_url: str,
        original_value: str,
        modified_value: str,
        vuln_type: str = "idor",
    ) -> VulnFinding | None:
        """Execute IDOR check using AuthManager profiles.
        
        Args:
            executor: Request executor
            target_url: The URL to test (e.g. /api/users/123)
            original_value: The original ID (123)
            modified_value: The manipulated ID (if any) or None
            
        Returns:
            VulnFinding if vulnerable, None otherwise
        """
        auth_manager = get_auth_manager()
        
        # Determine strategy based on available profiles
        if auth_manager.has_multiple_users():
            return await self._check_dual_user(
                executor, auth_manager, target_url, original_value
            )
        else:
            return await self._check_single_user(
                executor, auth_manager, target_url
            )
    
    async def _check_dual_user(
        self,
        executor: "ConcurrentExecutor",
        auth_manager,
        target_url: str,
        resource_id: str,
    ) -> VulnFinding | None:
        """Strategy 2: Dual User (Horizontal Escalation).
        
        Scenario:
        - Victim (Owner) owns resource_id
        - Attacker tries to access resource_id
        """
        victim, attacker = auth_manager.get_victim_attacker_pair()
        
        if not victim or not attacker:
            logger.warning("[IDOR] Dual user strategy requires 'victim' and 'attacker' profiles")
            return None
            
        logger.info(f"[IDOR] Dual User Check: Attacker '{attacker.name}' -> Victim resource '{target_url}'")
        
        from trix.engine.scan_task import ScanTask, TaskType
        
        # 1. Baseline: Victim accesses their own resource
        task_baseline = ScanTask(
            scan_id="temp",
            task_type=TaskType.URL,
            target=target_url,
        )
        resp_baseline = await executor.execute_request(task_baseline, auth_profile=victim.name)
        
        if resp_baseline["status_code"] not in (200, 201, 202):
            logger.debug(f"[IDOR] Baseline failed (Status {resp_baseline['status_code']}). Skipping.")
            return None
            
        # 2. Attack: Attacker accesses Victim's resource
        # Executor will inject Attacker's cookies automatically via auth_profile
        resp_attack = await executor.execute_request(task_baseline, auth_profile=attacker.name)
        
        # 3. Compare Results
        if resp_attack["status_code"] in (200, 201, 202):
            similarity = self._calculate_similarity(resp_baseline["body"], resp_attack["body"])
            logger.info(f"[IDOR] Attack Status: {resp_attack['status_code']}, Similarity: {similarity:.2f}")
            
            if similarity > 0.85:
                return VulnFinding(
                    target=target_url,
                    vuln_type="idor",
                    payload=f"Auth Profile: {attacker.name} (Attacker)",
                    raw_request=f"GET {target_url} [Cookies: {attacker.cookies}]",
                    raw_response=resp_attack["body"][:500],
                    confidence_score=0.9,
                    risk_level="high",
                    description=f"IDOR detected! User '{attacker.name}' could access resource owned by '{victim.name}'.",
                    plugin_name=self.name,
                    evidence={
                        "baseline_status": resp_baseline["status_code"],
                        "attack_status": resp_attack["status_code"],
                        "similarity": similarity,
                        "resource_id": resource_id,
                    }
                )
        
        return None

    async def _check_single_user(
        self,
        executor: "ConcurrentExecutor",
        auth_manager,
        target_url: str,
    ) -> VulnFinding | None:
        """Strategy 1: Single User (Authorization Bypass).
        
        Scenario:
        - Authenticated user can access resource
        - Anonymous user tries to access same resource
        """
        # Get any authenticated profile (prefer 'victim' or first available)
        profiles = auth_manager.list_profiles()
        valid_profiles = [p for p in profiles if p.name != "anonymous"]
        
        if not valid_profiles:
            logger.warning("[IDOR] Single user strategy requires at least one authenticated profile")
            return None
            
        auth_user = valid_profiles[0]
        
        logger.info(f"[IDOR] Single User Check: Anonymous -> Resource '{target_url}' (Owner: {auth_user.name})")
        
        from trix.engine.scan_task import ScanTask, TaskType
        
        # 1. Baseline: Authenticated access
        task_baseline = ScanTask(
            scan_id="temp",
            task_type=TaskType.URL,
            target=target_url,
        )
        resp_baseline = await executor.execute_request(task_baseline, auth_profile=auth_user.name)
        
        if resp_baseline["status_code"] not in (200, 201, 202):
            return None
            
        # 2. Attack: Anonymous access (no auth_profile)
        resp_attack = await executor.execute_request(task_baseline, auth_profile=None)
        
        # 3. Judgment
        # If Anonymous gets 200 OK and content is similar -> Bypass
        if resp_attack["status_code"] in (200, 201, 202):
            similarity = self._calculate_similarity(resp_baseline["body"], resp_attack["body"])
            
            if similarity > 0.85:
                return VulnFinding(
                    target=target_url,
                    vuln_type="broken_access_control",
                    payload="<Anonymous Request>",
                    raw_request=f"GET {target_url} [No Cookies]",
                    raw_response=resp_attack["body"][:500],
                    confidence_score=0.8,
                    risk_level="medium",
                    description="Authorization Bypass! Anonymous user accessed protected resource.",
                    plugin_name=self.name,
                    evidence={
                        "baseline_user": auth_user.name,
                        "similarity": similarity,
                    }
                )
                
        return None

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate simple text similarity (0.0 - 1.0)."""
        import difflib
        return difflib.SequenceMatcher(None, text1, text2).ratio()
