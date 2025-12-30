"""OpenAI-compatible LLM Judge implementation.

Uses litellm for broad model compatibility (OpenAI, Claude, local models, etc.)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import litellm
from tenacity import retry, stop_after_attempt, wait_exponential

from trix.brain.llm_judge import LLMJudge
from trix.models.finding import ConfidenceLevel, RiskLevel, VulnFinding
from trix.models.judgment import JudgmentRequest, JudgmentResult

logger = logging.getLogger(__name__)


class OpenAIJudge(LLMJudge):
    """LLM Judge implementation using OpenAI-compatible APIs.
    
    Supports any model through litellm:
    - OpenAI: gpt-4o, gpt-4o-mini
    - Anthropic: claude-3-5-sonnet
    - Local: ollama/llama3
    - And more...
    
    Example:
        judge = OpenAIJudge(model="gpt-4o-mini")
        result = await judge.judge(request)
    """
    
    def __init__(
        self,
        model: str = None,
        api_key: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
    ):
        """Initialize the OpenAI Judge.
        
        Args:
            model: Model name (litellm format). Defaults to LITELLM_MODEL env var or gpt-4o-mini
            api_key: API key (defaults to env var)
            temperature: LLM temperature (lower = more deterministic)
            max_tokens: Maximum tokens for response
        """
        # Model selection: env var > constructor arg > default
        self.model = model or os.getenv("LITELLM_MODEL") or "gpt-4o-mini"
        
        # API Key: try multiple env vars for different providers
        self.api_key = (
            api_key or 
            os.getenv("DEEPSEEK_API_KEY") or 
            os.getenv("OPENAI_API_KEY") or 
            os.getenv("LLM_API_KEY")
        )
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        # Configure litellm
        if self.api_key:
            litellm.api_key = self.api_key
    
    @retry(
        stop=stop_after_attempt(3), 
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    async def judge(self, request: JudgmentRequest) -> JudgmentResult:
        """Execute LLM judgment on a single request."""
        
        # Build prompts
        system_prompt = self.build_system_prompt(request.vuln_type)
        user_prompt = self._build_user_prompt(request)
        
        try:
            # Call LLM
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
            )
            
            # Parse response
            content = response.choices[0].message.content
            return self._parse_response(content)
            
        except Exception as e:
            logger.error(f"LLM judgment failed: {e}")
            return JudgmentResult.create_negative(
                reasoning=f"LLM analysis failed: {str(e)}"
            )
    
    async def batch_judge(
        self, 
        requests: list[JudgmentRequest]
    ) -> list[JudgmentResult]:
        """Batch judgment for multiple requests.
        
        Currently processes sequentially, but could be optimized
        to batch similar requests into single LLM calls.
        """
        results = []
        for request in requests:
            result = await self.judge(request)
            results.append(result)
        return results
    
    async def analyze_false_positive(
        self,
        finding: VulnFinding,
        additional_context: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Analyze whether a finding is a false positive."""
        
        prompt = f"""Analyze this vulnerability finding and determine if it's a false positive.

## Finding Details:
- Vulnerability Type: {finding.vuln_type}
- Target: {finding.target}
- Payload: {finding.payload}
- Original Confidence: {finding.confidence_score:.0%}
- Original Reasoning: {finding.llm_reasoning}

## Evidence:
{chr(10).join(f'- {e}' for e in finding.evidence)}

## HTTP Response:
```
{finding.raw_response[:3000]}
```

{f'## Additional Context: {additional_context}' if additional_context else ''}

Respond with JSON: {{"is_false_positive": boolean, "reasoning": "..."}}
"""
        
        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert reviewing potential false positives."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=500,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            data = json.loads(content)
            return data.get("is_false_positive", False), data.get("reasoning", "")
            
        except Exception as e:
            logger.error(f"False positive analysis failed: {e}")
            return False, f"Analysis failed: {e}"
    
    async def suggest_mutations(
        self,
        vuln_type: str,
        failed_payloads: list[str],
        response_patterns: list[str],
    ) -> list[str]:
        """Suggest payload mutations when current payloads fail."""
        
        # Load vuln-specific knowledge
        vuln_knowledge = self.get_vuln_prompt(vuln_type)
        
        prompt = f"""Based on the failed payloads and observed response patterns,
suggest new payload variations that might bypass defenses.

## Vulnerability Type: {vuln_type}

## Failed Payloads:
{chr(10).join(f'- {p}' for p in failed_payloads[:10])}

## Observed Response Patterns:
{chr(10).join(f'- {p}' for p in response_patterns[:10])}

{f'## Vulnerability Knowledge:{chr(10)}{vuln_knowledge[:2000]}' if vuln_knowledge else ''}

Suggest 5-10 new payload variations. Consider:
- Encoding bypasses (URL, Unicode, HTML entities)
- WAF evasion techniques
- Alternative syntax
- Case variations
- Comment injection

Respond with JSON: {{"suggestions": ["payload1", "payload2", ...]}}
"""
        
        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security researcher specializing in payload crafting."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,  # Higher for creativity
                max_tokens=1000,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            data = json.loads(content)
            return data.get("suggestions", [])
            
        except Exception as e:
            logger.error(f"Mutation suggestion failed: {e}")
            return []
    
    async def generate_verification_task(
        self,
        request: JudgmentRequest,
        result: JudgmentResult,
        task_id: str,
        parent_task_id: str | None = None,
        depth: int = 0,
    ) -> "VerificationTask | None":
        """Generate a verification task for uncertain findings.
        
        When confidence is between 50-80%, generate a new payload to confirm.
        """
        from trix.models.verification import (
            VerificationTask,
            VerificationReason,
            VerificationPriority,
            MAX_VERIFICATION_DEPTH,
        )
        
        # Check recursion depth limit
        if depth >= MAX_VERIFICATION_DEPTH:
            logger.warning(f"Max verification depth ({MAX_VERIFICATION_DEPTH}) reached")
            return None
        
        # Determine reason and priority based on result
        reason = VerificationReason.UNCERTAIN_CONFIDENCE
        priority = VerificationPriority.HIGH
        
        if result.waf_detected:
            reason = VerificationReason.WAF_BYPASS_NEEDED
            priority = VerificationPriority.NORMAL
        elif "time" in request.vuln_type.lower() or "delay" in result.reasoning.lower():
            reason = VerificationReason.TIME_DELAY_INCONCLUSIVE
            priority = VerificationPriority.HIGH
        elif result.mutation_suggestions:
            reason = VerificationReason.MUTATION_SUGGESTED
        
        # Build prompt for LLM to generate verification payload
        prompt = f"""你是一名资深渗透测试工程师。之前的漏洞测试结果不确定(置信度: {result.confidence_score*100:.0f}%)。

## 原始测试信息
- 目标: {request.target}
- 参数: {request.payload}
- 漏洞类型: {request.vuln_type}
- 原始 Payload: {request.payload}

## 上一次判断结果
- 推理过程: {result.reasoning[:500]}
- 证据: {', '.join(result.evidence[:3]) if result.evidence else '无'}
- 问题: {', '.join(result.false_positive_reasons[:2]) if result.false_positive_reasons else '证据不足'}

## 你的任务
生成一个新的验证 Payload,用于确认或排除漏洞。

考虑以下策略:
1. 如果是时间盲注不确定,增加延迟时间(如从2秒改为5秒)
2. 如果是布尔盲注不确定,尝试更明显的真/假条件
3. 如果被 WAF 拦截,尝试编码绕过
4. 如果是 XSS 不确定,尝试不同的事件处理器或编码

请返回 JSON:
{{
    "verification_payload": "新的验证 Payload",
    "verification_instruction": "AI 应该关注响应中的什么特征来判断",
    "expected_behavior": "如果漏洞存在,预期会看到什么",
    "reasoning": "为什么选择这个验证策略"
}}
"""
        
        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是漏洞验证专家,负责生成精确的验证 Payload。"},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=800,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            data = json.loads(content)
            
            # Create verification task
            return VerificationTask(
                task_id=task_id,
                parent_task_id=parent_task_id,
                depth=depth + 1,
                target_url=request.target,
                parameter=request.payload,  # Note: This should be the parameter name
                vuln_type=request.vuln_type,
                original_payload=request.payload,
                verification_payload=data.get("verification_payload", ""),
                reason=reason,
                priority=priority,
                verification_instruction=data.get("verification_instruction", ""),
                expected_behavior=data.get("expected_behavior", ""),
                previous_confidence=result.confidence_score,
                previous_reasoning=result.reasoning,
                previous_evidence=result.evidence,
            )
            
        except Exception as e:
            logger.error(f"Failed to generate verification task: {e}")
            return None
    
    def _build_user_prompt(self, request: JudgmentRequest) -> str:
        """Build the user prompt from the judgment request.
        
        Enhanced to require chain-of-thought reasoning and WAF analysis.
        """
        return f"""你是一位拥有 10 年经验的高级渗透测试工程师。你不仅仅是看报错，你会分析上下文、过滤 WAF 的干扰、判断回显的逻辑一致性。

## 分析目标
分析此 HTTP 请求/响应是否存在 **{request.vuln_type}** 漏洞。

{request.to_prompt_context()}

## 你必须执行的分析步骤 (Chain of Thought)

请按照以下步骤进行分析,并在 reasoning_trace 字段中详细记录每一步:

### Step 1: WAF/防护检测
- 检查响应是否包含 WAF 特征 (Cloudflare, ModSecurity, AWS WAF, etc.)
- 识别是否有通用的拦截页面或 403/406 响应
- 记录检测到的防护类型

### Step 2: 响应差异分析
- 对比 Baseline 响应和 Payload 响应
- 分析响应长度、状态码、关键内容的差异
- 判断差异是否由 Payload 引起而非随机因素

### Step 3: 漏洞指纹识别
- 寻找 {request.vuln_type} 的具体报错指纹
- 确认是否有信息泄露(数据库类型、版本、表名等)
- 验证 Payload 是否在响应中被执行或回显

### Step 4: 误报过滤
- 排除普通的 403/500 错误(不是漏洞证据)
- 排除 WAF 拦截页面(被拦截 ≠ 漏洞存在)
- 排除静态页面的随机差异

### Step 5: 最终判定
- 只有当存在 **确凿证据** 时才判定为 True
- 确凿证据包括: SQL 报错指纹、XSS 执行上下文、时间延迟验证等
- 如果证据不足,判定为 False 并建议后续测试

## 期望行为
{request.expected_behavior}

## JSON 响应格式

请返回严格符合以下 Schema 的 JSON:

{{
    "is_vulnerable": boolean,
    "confidence_score": float (0-100 的整数映射到 0.0-1.0),
    "risk_level": "critical" | "high" | "medium" | "low" | "info",
    "reasoning": "一句话总结判定结果",
    "reasoning_trace": "Markdown 格式的详细分析过程,包含上述每个步骤的分析记录",
    "evidence": ["证据1", "证据2"],
    "evidence_snippet": "从响应中提取的证明漏洞存在的具体片段(如 SQL 报错信息)",
    "waf_detected": boolean,
    "waf_type": "检测到的 WAF 类型,如 Cloudflare/ModSecurity/None",
    "false_positive_reasons": ["如果判定为 False,列出排除的理由"],
    "mutation_suggestions": ["如果需要进一步测试,建议的 Payload 变体"]
}}
"""
    
    def _parse_response(self, content: str) -> JudgmentResult:
        """Parse LLM response into JudgmentResult.
        
        Enhanced to extract reasoning_trace, evidence_snippet, and WAF detection fields.
        """
        try:
            data = json.loads(content)
            
            # Map risk level
            risk_map = {
                "critical": RiskLevel.CRITICAL,
                "high": RiskLevel.HIGH,
                "medium": RiskLevel.MEDIUM,
                "low": RiskLevel.LOW,
                "info": RiskLevel.INFO,
            }
            
            # Map confidence level (handle both 0-1 and 0-100 scales)
            raw_score = data.get("confidence_score", 0.0)
            score = raw_score / 100.0 if raw_score > 1.0 else raw_score
            
            if score >= 0.9:
                conf_level = ConfidenceLevel.CONFIRMED
            elif score >= 0.7:
                conf_level = ConfidenceLevel.LIKELY
            elif score >= 0.4:
                conf_level = ConfidenceLevel.SUSPECTED
            else:
                conf_level = ConfidenceLevel.FALSE_POSITIVE
            
            # Extract WAF detection info
            waf_detected = data.get("waf_detected", False)
            waf_type = data.get("waf_type", "")
            if waf_type and waf_type.lower() in ("none", "无", "未检测到"):
                waf_type = ""
                waf_detected = False
            
            return JudgmentResult(
                is_vulnerable=data.get("is_vulnerable", False),
                confidence_score=score,
                confidence_level=conf_level,
                risk_level=risk_map.get(data.get("risk_level", "info"), RiskLevel.INFO),
                reasoning=data.get("reasoning", ""),
                reasoning_trace=data.get("reasoning_trace", ""),
                evidence=data.get("evidence", []),
                evidence_snippet=data.get("evidence_snippet", ""),
                waf_detected=waf_detected,
                waf_type=waf_type,
                waf_bypass_attempted=bool(waf_detected and data.get("is_vulnerable", False)),
                is_false_positive=not data.get("is_vulnerable", False),
                false_positive_reasons=data.get("false_positive_reasons", []),
                needs_further_testing=bool(data.get("mutation_suggestions")),
                mutation_suggestions=data.get("mutation_suggestions", []),
                raw_llm_response=content,
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}\nContent: {content[:500]}")
            return JudgmentResult.create_negative(
                reasoning=f"Failed to parse LLM response: {e}"
            )
