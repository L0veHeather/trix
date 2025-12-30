"""Scan Controller - Orchestrates the LLM-driven scanning flow.

This is the main coordinator that:
1. Takes targets and plugins as input
2. Uses plugins to generate payloads (no judgment)
3. Sends HTTP requests (deterministic logic)
4. Submits responses to LLM for judgment (AI Brain)
5. Collects and returns standardized findings
6. [NEW] Implements feedback loop for uncertain findings (50-80% confidence)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import deque
from dataclasses import dataclass
from typing import AsyncIterator, Any

import httpx

from trix.brain.llm_judge import LLMJudge
from trix.models.finding import VulnFinding
from trix.models.judgment import JudgmentRequest, JudgmentResult
from trix.models.request import HttpRequest, HttpResponse, ScanTarget
from trix.models.verification import (
    VerificationTask,
    VerificationPriority,
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_UNCERTAIN_HIGH,
    CONFIDENCE_UNCERTAIN_LOW,
    MAX_VERIFICATION_DEPTH,
    MAX_VERIFICATION_ATTEMPTS,
)
from trix.plugins.vulns import BaseVulnPlugin, PayloadContext, PayloadSpec

logger = logging.getLogger(__name__)


class ScanController:
    """Main scan controller - orchestrates LLM-driven vulnerability scanning.
    
    Architecture:
    - Controller handles: task scheduling, HTTP requests, concurrency
    - Plugin handles: payload generation
    - LLM handles: vulnerability judgment
    
    Usage:
        controller = ScanController(llm_judge=OpenAIJudge())
        async for finding in controller.scan(target, plugins):
            print(finding)
    """
    
    def __init__(
        self,
        llm_judge: LLMJudge,
        max_concurrent: int = 10,
        timeout: float = 30.0,
        verify_ssl: bool = False,
    ):
        """Initialize the controller.
        
        Args:
            llm_judge: LLM judge instance for vulnerability analysis
            max_concurrent: Maximum concurrent HTTP requests
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.llm_judge = llm_judge
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self._semaphore: asyncio.Semaphore | None = None
        self._client: httpx.AsyncClient | None = None
        
        # === Feedback Loop State ===
        # Priority queue for verification tasks (high priority at front)
        self._verification_queue: deque[VerificationTask] = deque()
        # Track verification attempts per finding chain
        self._verification_attempts: dict[str, int] = {}
        # Enable/disable recursive verification
        self.enable_feedback_loop: bool = True
        
        # Statistics
        self.stats = {
            "requests_sent": 0,
            "payloads_tested": 0,
            "findings_confirmed": 0,
            "llm_calls": 0,
            "verification_tasks_generated": 0,
            "verification_tasks_resolved": 0,
        }
    
    async def __aenter__(self) -> "ScanController":
        """Enter async context."""
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
        )
        return self
    
    async def __aexit__(self, *args) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
        self._client = None
        self._semaphore = None
    
    async def scan(
        self,
        target: ScanTarget,
        plugins: list[BaseVulnPlugin],
    ) -> AsyncIterator[VulnFinding]:
        """Scan a target with multiple plugins.
        
        Main scanning flow:
        1. Get baseline response
        2. For each plugin, generate payloads
        3. Send requests concurrently
        4. Submit to LLM for judgment
        5. Yield confirmed findings
        
        Args:
            target: Target to scan
            plugins: List of vulnerability plugins
            
        Yields:
            VulnFinding for each confirmed vulnerability
        """
        if not self._client:
            raise RuntimeError("Controller not started. Use 'async with' context.")
        
        # Get baseline response
        baseline = await self._get_baseline(target)
        
        # Scan with each plugin
        for plugin in plugins:
            if not plugin.enabled:
                continue
            
            logger.info(f"Scanning with plugin: {plugin.name}")
            
            async for finding in self._scan_with_plugin(target, plugin, baseline):
                yield finding
    
    async def scan_parameter(
        self,
        target: ScanTarget,
        parameter: str,
        plugins: list[BaseVulnPlugin],
    ) -> AsyncIterator[VulnFinding]:
        """Scan a specific parameter with multiple plugins.
        
        Args:
            target: Target to scan
            parameter: Parameter name to test
            plugins: List of vulnerability plugins
            
        Yields:
            VulnFinding for each confirmed vulnerability
        """
        # Get baseline
        baseline = await self._get_baseline(target)
        
        for plugin in plugins:
            if not plugin.enabled:
                continue
            
            # Create context
            context = PayloadContext(
                target=target.url,
                parameter=parameter,
                method=target.method,
            )
            
            # Generate payloads
            payloads = plugin.generate_payloads(context)
            
            # Test each payload
            for payload in payloads:
                finding = await self._test_payload(
                    target, parameter, plugin, payload, baseline
                )
                if finding:
                    yield finding
    
    async def _get_baseline(self, target: ScanTarget) -> HttpResponse:
        """Get baseline response without any payloads."""
        try:
            response = await self._client.request(
                target.method,
                target.url,
                headers=target.headers,
            )
            
            return HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text[:10000],
                response_time_ms=response.elapsed.total_seconds() * 1000,
            )
        except Exception as e:
            logger.error(f"Failed to get baseline: {e}")
            return HttpResponse(status_code=0, error=str(e))
    
    async def _scan_with_plugin(
        self,
        target: ScanTarget,
        plugin: BaseVulnPlugin,
        baseline: HttpResponse,
    ) -> AsyncIterator[VulnFinding]:
        """Scan target with a single plugin."""
        
        # For each parameter
        for parameter in target.parameters or ["id", "q", "search", "page"]:
            context = PayloadContext(
                target=target.url,
                parameter=parameter,
                method=target.method,
            )
            
            # Generate payloads
            payloads = plugin.generate_payloads(context)
            logger.debug(f"Generated {len(payloads)} payloads for {parameter}")
            
            # Test payloads concurrently
            tasks = [
                self._test_payload(target, parameter, plugin, payload, baseline)
                for payload in payloads
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, VulnFinding):
                    yield result
                elif isinstance(result, Exception):
                    logger.warning(f"Payload test failed: {result}")
    
    async def _test_payload(
        self,
        target: ScanTarget,
        parameter: str,
        plugin: BaseVulnPlugin,
        payload_spec: PayloadSpec,
        baseline: HttpResponse,
        verification_task: VerificationTask | None = None,
    ) -> VulnFinding | None:
        """Test a single payload and get LLM judgment.
        
        Flow:
        1. Send HTTP request with payload
        2. Build judgment request
        3. Submit to LLM
        4. [NEW] Check confidence - if uncertain, spawn verification task
        5. Process result through plugin
        """
        async with self._semaphore:
            self.stats["payloads_tested"] += 1
            
            # Use verification payload if this is a verification task
            actual_payload = (
                verification_task.verification_payload 
                if verification_task 
                else payload_spec.payload
            )
            
            # 1. Send HTTP request with payload
            request, response = await self._send_payload_request(
                target, parameter, actual_payload
            )
            self.stats["requests_sent"] += 1
            
            if response.error:
                return None
            
            # 2. Build judgment request
            expected_behavior = (
                verification_task.expected_behavior
                if verification_task
                else payload_spec.expected_behavior
            )
            
            judgment_request = JudgmentRequest(
                vuln_type=plugin.vuln_type,
                target=target.url,
                payload=actual_payload,
                raw_request=request.to_raw(),
                raw_response=response.to_raw(),
                baseline_response=baseline.to_raw(),
                response_time_ms=response.response_time_ms,
                baseline_time_ms=baseline.response_time_ms,
                context=plugin.get_judgment_context(payload_spec),
                expected_behavior=expected_behavior,
            )
            
            # 3. Submit to LLM
            self.stats["llm_calls"] += 1
            judgment_result = await self.llm_judge.judge(judgment_request)
            
            # 4. [NEW] Feedback Loop - Check if confidence is uncertain
            finding = await self._process_judgment_with_feedback(
                judgment_request,
                judgment_result,
                plugin,
                payload_spec,
                request,
                response,
                target,
                verification_task,
            )
            
            return finding
    
    async def _process_judgment_with_feedback(
        self,
        judgment_request: JudgmentRequest,
        judgment_result: JudgmentResult,
        plugin: BaseVulnPlugin,
        payload_spec: PayloadSpec,
        request: HttpRequest,
        response: HttpResponse,
        target: ScanTarget,
        verification_task: VerificationTask | None = None,
    ) -> VulnFinding | None:
        """Process judgment with feedback loop for uncertain findings.
        
        Confidence Zones:
        - >= 80%: Confirmed (return finding)
        - 50-80%: Uncertain (spawn verification task)
        - < 50%: Rejected (return None)
        """
        confidence = judgment_result.confidence_score
        
        # Track chain ID for attempt limiting
        chain_id = (
            verification_task.parent_task_id or verification_task.task_id
            if verification_task
            else str(uuid.uuid4())[:8]
        )
        
        # === HIGH CONFIDENCE: Confirmed ===
        if confidence >= CONFIDENCE_CONFIRMED:
            finding = plugin.process_judgment(
                payload_spec,
                judgment_result,
                request.to_raw(),
                response.to_raw(),
                target.url,
            )
            if finding:
                self.stats["findings_confirmed"] += 1
                if verification_task:
                    self.stats["verification_tasks_resolved"] += 1
                logger.info(f"[+] CONFIRMED {plugin.vuln_type}: {target.url} (confidence: {confidence:.0%})")
            return finding
        
        # === LOW CONFIDENCE: May trigger AI bypass ===
        if confidence < CONFIDENCE_UNCERTAIN_LOW:
            if verification_task:
                self.stats["verification_tasks_resolved"] += 1
            
            # 🔥 Check if AI bypass should be triggered (30-50% confidence range)
            # This suggests WAF/filter blocking, not lack of vulnerability
            if plugin.use_ai_generation and 0.30 <= confidence < 0.50:
                logger.info(
                    f"[AI-Bypass] Triggering smart payload generation for {plugin.vuln_type} "
                    f"(confidence: {confidence:.0%})"
                )
                
                # Store for later AI payload testing
                self._pending_ai_payloads = getattr(self, '_pending_ai_payloads', [])
                self._pending_ai_payloads.append({
                    "plugin": plugin,
                    "payload_spec": payload_spec,
                    "context": PayloadContext(
                        target=target.url,
                        parameter=judgment_request.target,
                        method=target.method,
                    ),
                    "raw_response": response.to_raw() if response else "",
                    "waf_type": judgment_result.waf_type if hasattr(judgment_result, 'waf_type') else "",
                })
                self.stats["ai_bypass_triggered"] = self.stats.get("ai_bypass_triggered", 0) + 1
            
            logger.debug(f"[-] Rejected {plugin.vuln_type}: confidence too low ({confidence:.0%})")
            return None
        
        # === UNCERTAIN ZONE (50-80%): Spawn Verification Task ===
        if not self.enable_feedback_loop:
            logger.debug(f"[?] Uncertain {plugin.vuln_type} ({confidence:.0%}), feedback loop disabled")
            return None
        
        # Check attempt limit
        current_attempts = self._verification_attempts.get(chain_id, 0)
        if current_attempts >= MAX_VERIFICATION_ATTEMPTS:
            logger.warning(f"[!] Max verification attempts ({MAX_VERIFICATION_ATTEMPTS}) reached for chain {chain_id}")
            return None
        
        # Check depth limit
        current_depth = verification_task.depth if verification_task else 0
        if current_depth >= MAX_VERIFICATION_DEPTH:
            logger.warning(f"[!] Max verification depth ({MAX_VERIFICATION_DEPTH}) reached")
            return None
        
        # Generate verification task
        new_task_id = str(uuid.uuid4())[:8]
        parent_id = verification_task.task_id if verification_task else chain_id
        
        logger.info(f"[?] Uncertain {plugin.vuln_type} ({confidence:.0%}), generating verification task...")
        
        new_verification_task = await self.llm_judge.generate_verification_task(
            request=judgment_request,
            result=judgment_result,
            task_id=new_task_id,
            parent_task_id=parent_id,
            depth=current_depth,
        )
        
        if new_verification_task:
            # Add to queue based on priority
            self._add_verification_task(new_verification_task)
            self._verification_attempts[chain_id] = current_attempts + 1
            self.stats["verification_tasks_generated"] += 1
            
            logger.info(
                f"[+] Verification task {new_task_id} created: "
                f"{new_verification_task.verification_payload[:50]}..."
            )
        
        return None
    
    def _add_verification_task(self, task: VerificationTask) -> None:
        """Add verification task to queue with priority handling.
        
        HIGH/CRITICAL priority tasks are added to the front of the queue.
        """
        if task.priority in (VerificationPriority.CRITICAL, VerificationPriority.HIGH):
            self._verification_queue.appendleft(task)  # Front of queue
        else:
            self._verification_queue.append(task)  # Back of queue
    
    def get_pending_verification_tasks(self) -> list[VerificationTask]:
        """Get all pending verification tasks."""
        return list(self._verification_queue)
    
    async def process_verification_queue(
        self,
        target: ScanTarget,
        plugin: BaseVulnPlugin,
        baseline: HttpResponse,
    ) -> AsyncIterator[VulnFinding]:
        """Process all pending verification tasks.
        
        This should be called after initial scanning to resolve uncertain findings.
        """
        while self._verification_queue:
            task = self._verification_queue.popleft()
            
            logger.info(f"[*] Processing verification task {task.task_id} (depth: {task.depth})")
            
            # Create a PayloadSpec from the verification task
            verification_payload_spec = PayloadSpec(
                payload=task.verification_payload,
                description=f"Verification for {task.original_payload}",
                expected_behavior=task.expected_behavior,
            )
            
            finding = await self._test_payload(
                target,
                task.parameter,
                plugin,
                verification_payload_spec,
                baseline,
                verification_task=task,
            )
            
            if finding:
                yield finding
    
    async def _send_payload_request(
        self,
        target: ScanTarget,
        parameter: str,
        payload: str,
    ) -> tuple[HttpRequest, HttpResponse]:
        """Send HTTP request with payload injected."""
        
        # Build URL with payload
        if target.method == "GET":
            url = target.url
            if "?" in url:
                url = f"{url}&{parameter}={payload}"
            else:
                url = f"{url}?{parameter}={payload}"
            params = {}
            body = ""
        else:
            url = target.url
            params = {parameter: payload}
            body = f"{parameter}={payload}"
        
        request = HttpRequest(
            method=target.method,
            url=url,
            headers=target.headers,
            body=body,
            params=params,
            injected_parameter=parameter,
            injected_payload=payload,
        )
        
        try:
            if target.method == "GET":
                resp = await self._client.get(url, headers=target.headers)
            else:
                resp = await self._client.request(
                    target.method,
                    target.url,
                    data=params,
                    headers=target.headers,
                )
            
            response = HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:10000],
                response_time_ms=resp.elapsed.total_seconds() * 1000,
            )
            
        except Exception as e:
            response = HttpResponse(status_code=0, error=str(e))
        
        return request, response
    
    def get_stats(self) -> dict[str, Any]:
        """Get scanning statistics."""
        return self.stats.copy()
    
    async def process_pending_ai_payloads(
        self,
        target: ScanTarget,
        baseline: HttpResponse,
    ) -> AsyncIterator[VulnFinding]:
        """Process pending AI-generated bypass payloads.
        
        Call this after initial scan to test AI-generated bypass payloads
        that were queued during the low-confidence detection phase.
        
        Yields:
            VulnFinding for each confirmed vulnerability
        """
        pending = getattr(self, '_pending_ai_payloads', [])
        if not pending:
            return
        
        logger.info(f"[AI-Bypass] Processing {len(pending)} pending AI payload requests...")
        self.stats["ai_payloads_tested"] = 0
        
        for item in pending:
            plugin = item["plugin"]
            context = item["context"]
            raw_response = item["raw_response"]
            waf_type = item["waf_type"]
            original_payload = item["payload_spec"].payload
            
            # Generate AI bypass payloads
            ai_payloads = await plugin.generate_ai_payloads(
                context=context,
                blocked_payload=original_payload,
                raw_response=raw_response,
                waf_type=waf_type,
            )
            
            if not ai_payloads:
                continue
            
            logger.info(
                f"[AI-Bypass] Testing {len(ai_payloads)} bypass payloads for {plugin.vuln_type}"
            )
            
            # Test each AI-generated payload
            for payload_spec in ai_payloads:
                self.stats["ai_payloads_tested"] += 1
                
                finding = await self._test_payload(
                    target,
                    context.parameter,
                    plugin,
                    payload_spec,
                    baseline,
                )
                
                if finding:
                    logger.info(
                        f"[AI-Bypass] SUCCESS! Bypass payload confirmed: "
                        f"{payload_spec.payload[:50]}..."
                    )
                    yield finding
        
        # Clear pending list
        self._pending_ai_payloads = []
        
        logger.info(
            f"[AI-Bypass] Completed. Tested {self.stats.get('ai_payloads_tested', 0)} payloads"
        )
