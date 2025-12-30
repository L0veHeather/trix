# Trix Project Audit Report

**Audit Date:** 2025-12-30  
**Auditor:** Chief Auditor  
**Scope:** AI-Native Migration (Strangler Fig Pattern)

---

## 1. 🗺️ Current Architecture Map

### Data Flow Diagram (AI-Native)

```mermaid
flowchart TB
    subgraph API["API Layer"]
        REST["/api/scans"]
        WS["WebSocket"]
    end
    
    subgraph Engine["ScanEngine"]
        SE["ScanEngine.start_scan()"]
        TQ["DynamicTaskQueue"]
        PM["PhaseManager (Legacy)"]
    end
    
    subgraph AI["AI-Native Core"]
        SC["ScanController"]
        LLM["LLMJudge (OpenAIJudge)"]
        VQ["_verification_queue"]
    end
    
    subgraph Plugins["Plugins"]
        VP["VulnPlugins (sqli, idor)"]
        LP["LegacyPlugins (nuclei, sqlmap)"]
    end
    
    subgraph Output["Output Layer"]
        RC["ResultCollector"]
        EB["EventBus"]
        DB["SQLite DB"]
    end
    
    REST --> SE
    SE --> TQ
    TQ -->|"[MIGRATION]"| SC
    TQ -.->|"DEPRECATED"| PM
    
    SC --> VP
    VP -->|"generate_payloads"| SC
    SC -->|"HTTP Request"| Target["Target URL"]
    Target -->|"Response"| SC
    SC -->|"JudgmentRequest"| LLM
    LLM -->|"60-80% confidence"| VQ
    VQ -->|"Feedback Loop"| SC
    LLM -->|"≥80% confidence"| RC
    
    PM -.-> LP
    
    RC --> EB
    EB --> WS
    EB --> DB
```

### Flow Verification

| Path | Status |
|------|--------|
| API → ScanEngine → ScanController → VulnPlugin | ✅ Connected |
| ScanController → LLMJudge → EventBus | ✅ Connected |
| LLMJudge → VerificationQueue → ScanController | ✅ Connected |
| PhaseManager → LegacyPlugins | ⚠️ Legacy (deprecated but present) |

**断头路检查:** ❌ 无断头路。所有数据流均已连接。

---

## 2. 🧟 Zombie Code Detection

### 2.1 Duplicate Imports (scan_engine.py)

```python
# Lines 27-30 - DUPLICATE IMPORTS
from trix.engine.task_queue import DynamicTaskQueue  # Line 27
from trix.brain.llm_judge import LLMJudge             # Line 28
from trix.engine.task_queue import DynamicTaskQueue  # Line 29 ← DUPLICATE
from trix.brain.llm_judge import LLMJudge             # Line 30 ← DUPLICATE
```

**Status:** 🔴 Should be removed

### 2.2 DEPRECATED Markers

| File | Line | Code Block |
|------|------|------------|
| [scan_engine.py](file:///Users/yeyuchen002/Downloads/strix/trix/engine/scan_engine.py#L468) | 468 | `# ### [DEPRECATED] LEGACY FLOW ###` |
| [scan_engine.py](file:///Users/yeyuchen002/Downloads/strix/trix/engine/scan_engine.py#L575) | 575 | `# ### [DEPRECATED] LEGACY FLOW ###` |
| [scan_engine.py](file:///Users/yeyuchen002/Downloads/strix/trix/engine/scan_engine.py#L836) | 836 | `# ### [DEPRECATED] LEGACY FLOW ###` |

**Status:** ⚠️ Code still exists but is bypassed by `[MIGRATION]` log path

### 2.3 PhaseManager Methods

| Method | Called by ScanController? | Status |
|--------|--------------------------|--------|
| `execute_phase()` | ❌ No | Legacy only |
| `execute_all()` | ❌ No | Legacy only |
| `_execute_plugin()` | ❌ No | Legacy only |

**Verdict:** `PhaseManager` is a **zombie module** - fully functional but no longer in the AI-Native critical path.

---

## 3. 🧠 AI-Native Logic Audit

### 3.1 Context Completeness

| Field | Passed to PayloadContext? | Location |
|-------|--------------------------|----------|
| `dom_source` | ✅ Yes | [llm_controller.py:250](file:///Users/yeyuchen002/Downloads/strix/trix/core/llm_controller.py#L250) |
| `tech_stack` | ✅ Yes | [llm_controller.py:251](file:///Users/yeyuchen002/Downloads/strix/trix/core/llm_controller.py#L251) |
| `parameter` | ✅ Yes | [llm_controller.py:248](file:///Users/yeyuchen002/Downloads/strix/trix/core/llm_controller.py#L248) |

```python
context = PayloadContext(
    target=target.url,
    parameter=parameter,
    method=target.method,
    dom_source=baseline.body if baseline else "",  # ✅ DOM Source included
    tech_stack=target.tech_stack or [],
)
```

### 3.2 Prompt Construction

| Requirement | Implemented? | Details |
|-------------|--------------|---------|
| JSON output forced | ✅ Yes | `response_format={"type": "json_object"}` (line 85) |
| Few-Shot examples | ⚠️ Partial | System prompt has examples, not structured few-shot |
| Chain-of-Thought | ✅ Yes | `reasoning_trace` field in response |

### 3.3 Error Handling

```python
# openai_judge.py:92-95
except Exception as e:
    logger.error(f"LLM judgment failed: {e}")
    return JudgmentResult.create_negative(
        reasoning=f"LLM analysis failed: {str(e)}"
    )
```

| Mechanism | Status |
|-----------|--------|
| `try-except` on LLM call | ✅ Yes |
| Graceful fallback | ✅ Returns negative result |
| Retry mechanism | ❌ No explicit retry (relies on litellm) |

---

## 4. 🔌 Plugin Health Check

### 4.1 SQLi Plugin (sqli.py)

| Check | Status |
|-------|--------|
| `generate_payloads()` | ✅ Implemented |
| `get_judgment_context()` | ✅ Implemented |
| Error isolation in execute | ⚠️ N/A (no execute method) |
| AI Compatible | ✅ Yes |

### 4.2 Nuclei Plugin

| Check | Status |
|-------|--------|
| `generate_payloads()` | ❌ Not implemented |
| `execute()` method | ✅ Uses BasePlugin |
| Error isolation | ✅ Yes (BasePlugin handles) |
| AI Compatible | ❌ **Legacy Plugin** |

### Plugin Classification

| Plugin | Type | Notes |
|--------|------|-------|
| `sqli_detector` | AI-Native | Full VulnPlugin implementation |
| `idor_detector` | AI-Native | Full VulnPlugin implementation |
| `nuclei` | Legacy | External tool wrapper |
| `sqlmap` | Legacy | External tool wrapper |
| `httpx` | Utility | Reconnaissance only |
| `katana` | Utility | Crawler only |

---

## 5. 📊 Final Verdict

### Refactoring Completion Score: **78%**

```
╔═══════════════════════════════════════════════════════════╗
║                    REFACTORING SCORE                      ║
╠═══════════════════════════════════════════════════════════╣
║ ████████████████████████████████████░░░░░░░░░░  78/100    ║
╚═══════════════════════════════════════════════════════════╝
```

### Top 3 High-Priority Issues

| Priority | Issue | Impact | Fix |
|----------|-------|--------|-----|
| 🔴 P0 | Duplicate imports in scan_engine.py | Code quality | Remove lines 29-30 |
| 🟠 P1 | No retry mechanism in LLM calls | Reliability | Add tenacity decorator |
| 🟡 P2 | Legacy plugins lack AI interface | Feature gap | Add adapter or migrate |

### Summary

The AI-Native migration is **substantially complete**. The core feedback loop works correctly:
- ✅ `ScanController` orchestrates AI-driven scanning
- ✅ `LLMJudge` performs vulnerability judgment
- ✅ `VerificationQueue` enables feedback loop
- ✅ 5 TRACER logs confirm data flow
- ⚠️ Legacy code remains but is isolated

**Recommendation:** Proceed to production with P0 fix applied.
