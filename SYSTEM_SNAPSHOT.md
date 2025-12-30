# SYSTEM_SNAPSHOT - Strix/Trix 系统架构快照

> 生成时间: 2025-12-30
> 目标: 深度架构审计，为重构提供依据

---

## 1. 📂 Project Structure (Tree)

```
strix/
├── start.sh                    # 一键启动脚本，启动 uvicorn 后端 + vite 前端
├── plugins/                    # 🔌 外部安全工具插件目录
│   ├── ffuf/plugin.py          #   目录爆破
│   ├── httpx/plugin.py         #   HTTP 探测
│   ├── katana/plugin.py        #   Web 爬虫
│   ├── nuclei/plugin.py        #   CVE/漏洞扫描
│   └── sqlmap/plugin.py        #   SQL 注入
├── desktop/                    # 前端 Tauri + React 桌面应用
│   └── src/
│       ├── lib/api.ts          #   HTTP API 客户端
│       ├── lib/websocket.ts    #   WebSocket 客户端
│       └── pages/              #   页面组件
├── trix/                       # ⚙️ 后端核心代码
│   ├── server/                 # 📡 API 接口层
│   │   ├── app.py              #   FastAPI 入口，全局异常处理
│   │   └── routes/
│   │       ├── scans.py        #   扫描 CRUD API
│   │       ├── plugins.py      #   插件管理 API
│   │       └── websocket.py    #   WebSocket 实时推送
│   ├── engine/                 # 🔥 核心引擎层
│   │   ├── scan_engine.py      #   扫描编排器，任务生命周期
│   │   ├── phase_manager.py    #   阶段管理，插件调度
│   │   └── event_bus.py        #   事件发布/订阅系统
│   ├── plugins/                # 插件系统核心
│   │   ├── base.py             #   插件抽象基类
│   │   ├── loader.py           #   动态加载器 (importlib)
│   │   └── registry.py         #   插件注册中心
│   ├── core/                   # 业务逻辑层
│   │   ├── llm_controller.py   #   🧠 LLM 驱动的漏洞判断控制器
│   │   ├── scan_controller.py  #   任务队列/状态管理
│   │   └── heartbeat.py        #   心跳监控
│   ├── llm/                    # AI 集成层
│   │   └── llm.py              #   LiteLLM 封装，内存压缩
│   ├── brain/                  # LLM 判断逻辑
│   │   └── llm_judge.py        #   漏洞判断接口
│   └── storage/                # 数据持久层
│       └── database.py         #   SQLite + SQLAlchemy
└── tests/                      # 测试目录
```

**核心定位:**
- **核心引擎**: `trix/engine/scan_engine.py`
- **插件目录**: `plugins/` (外部工具) + `trix/plugins/` (框架代码)
- **API 接口层**: `trix/server/routes/`

---

## 2. 🏗 Architecture & Data Flow

### 2.1 启动流程

```
start.sh
    ↓ ./start.sh dev
    ├─→ setup_python_env()          # 创建 .venv，安装依赖
    ├─→ start_backend()             # nohup uvicorn trix.server.app:app --port 8000
    └─→ start_frontend()            # pnpm dev (vite on port 5173)

uvicorn 加载 trix.server.app:app
    ↓
trix/server/app.py::lifespan()
    ├─→ get_database()              # 初始化 SQLite
    └─→ get_plugin_registry().initialize()  # 扫描 plugins/ 目录，加载插件
```

**关键入口文件**: [app.py](file:///Users/yeyuchen002/Downloads/strix/trix/server/app.py)

```python
# trix/server/app.py (核心片段)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database
    db = get_database()
    # Initialize plugin registry (已改造: 不会因插件失败而崩溃)
    registry = get_plugin_registry()
    await registry.initialize()  # 返回 PluginLoadResult{valid, invalid}
    yield
```

---

### 2.2 任务流转

```
[Desktop Frontend]
    ↓ POST /api/scans {target, plugins, phases}
[trix/server/routes/scans.py]
    ↓ engine.start_scan(ScanConfig)
[trix/engine/scan_engine.py::ScanEngine]
    ↓ asyncio.create_task(_run_scan)
    ├─→ PhaseManager.execute_all()      # 遍历阶段
    │       ↓
    │   [trix/engine/phase_manager.py]
    │       ├─→ registry.execute(plugin_name, target)  # 执行插件
    │       │       ↓
    │       │   [trix/plugins/registry.py::PluginRegistry.execute]
    │       │       ↓ plugin.execute(target, phase, params)
    │       │   [plugins/nuclei/plugin.py 等]
    │       │       └─→ run_command(["nuclei", "-t", target])
    │       │       └─→ yield PluginEvent(output/vulnerability)
    │       │
    │       └─→ LLM 判断 (可选，见下节)
    │
    ├─→ ResultCollector.add_findings()  # 收集结果
    └─→ db.add_vulnerability()          # 持久化
```

**LLM 介入点** (在 `llm_controller.py` 中):
```python
# trix/core/llm_controller.py 核心流程
async def _test_payload():
    # 1. 发送 HTTP 请求
    request, response = await _send_payload_request(target, param, payload)
    # 2. 构建判断请求
    judgment_request = JudgmentRequest(vuln_type, payload, response, ...)
    # 3. 提交给 LLM 判断
    judgment_result = await self.llm_judge.judge(judgment_request)
    # 4. 置信度反馈循环 (50-80% → 生成验证任务)
    if CONFIDENCE_UNCERTAIN_LOW <= confidence < CONFIDENCE_CONFIRMED:
        new_task = await llm_judge.generate_verification_task(...)
```

---

### 2.3 状态同步机制

**使用 WebSocket 实时推送**，代码位置: [websocket.py](file:///Users/yeyuchen002/Downloads/strix/trix/server/routes/websocket.py)

```
后端事件流:
    ScanEngine → EventBus.publish(Event) → WebSocket handlers → ConnectionManager.broadcast()
                         ↓
                  EventType.SCAN_STARTED
                  EventType.SCAN_PROGRESS
                  EventType.VULNERABILITY_FOUND
                  EventType.PLUGIN_ERROR  ← [新增] 插件错误推送
                  EventType.SCAN_COMPLETED

前端订阅:
    WebSocket.connect("/ws/{clientId}")
    → send({action: "subscribe", scan_id: "xxx"})
    → 接收 {type: "scan.progress", data: {...}}
```

**关键代码片段**:
```python
# trix/server/routes/websocket.py
def setup_event_bus_handlers():
    event_bus = get_event_bus()
    
    async def handle_vulnerability_found(event: Event):
        scan_id = event.scan_id
        await manager.broadcast_to_scan(scan_id, {
            "type": "vulnerability.found",
            "data": event.data,
        })
    
    event_bus.subscribe(EventType.VULNERABILITY_FOUND, handle_vulnerability_found)
```

---

## 3. 🧠 Core Capabilities (Status Check)

### 3.1 Plugin System

| 方面 | 实现现状 | 局限性 |
|------|----------|--------|
| **加载机制** | `PluginLoader.load_plugin_class()` 使用 `importlib.util` 动态加载 `plugins/xxx/plugin.py` | ✅ 已改造: 异常隔离，返回 `PluginLoadResult{valid, invalid}` |
| **注册中心** | `PluginRegistry.initialize()` 遍历发现并加载 | ✅ 单个插件失败不影响其他 |
| **执行机制** | `PluginRegistry.execute()` 调用 `plugin.execute()` 生成器 | ✅ 已改造: 异常捕获 + 发布 `PLUGIN_ERROR` 事件 |

**插件加载代码** ([loader.py](file:///Users/yeyuchen002/Downloads/strix/trix/plugins/loader.py#L144)):
```python
def load_plugin_class(self, plugin_name: str) -> type[BasePlugin]:
    spec = importlib.util.spec_from_file_location(f"strix_plugins.{plugin_name}", plugin_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # ← 这里可能抛出任何异常
    # 查找 BasePlugin 子类...
```

---

### 3.2 AI Integration

| 方面 | 实现现状 | 局限性 |
|------|----------|--------|
| **介入环节** | 漏洞判断阶段 (`llm_controller.py`) | 仅做判断，不参与决策或规划 |
| **判断逻辑** | `LLMJudge.judge(JudgmentRequest) → JudgmentResult{is_vulnerable, confidence_score}` | 需要构造完整 HTTP 请求/响应上下文 |
| **反馈循环** | 置信度 50-80% 时生成验证任务 | MAX_VERIFICATION_ATTEMPTS=3, MAX_DEPTH=2 |
| **LLM 客户端** | `trix/llm/llm.py` 使用 LiteLLM 封装，支持 OpenAI/Anthropic/Ollama | 有内存压缩、Prompt Caching |

**AI 判断流程** ([llm_controller.py](file:///Users/yeyuchen002/Downloads/strix/trix/core/llm_controller.py#L244)):
```python
async def _test_payload(...):
    # 1. 发送 payload 请求
    request, response = await self._send_payload_request(target, parameter, payload)
    # 2. 构建判断请求
    judgment_request = JudgmentRequest(
        vuln_type=plugin.vuln_type,
        payload=payload,
        raw_request=request.to_raw(),
        raw_response=response.to_raw(),
        expected_behavior=payload_spec.expected_behavior,
    )
    # 3. LLM 判断
    judgment_result = await self.llm_judge.judge(judgment_request)
    # 4. 处理反馈循环
    if confidence >= 0.80: return finding  # 确认
    if confidence < 0.50: return None      # 拒绝
    # 50-80%: 生成验证任务
```

---

### 3.3 Execution Engine

| 方面 | 实现现状 | 局限性 |
|------|----------|--------|
| **并发模型** | `asyncio` 协程，`asyncio.gather()` 并发执行插件 | 单进程，受 GIL 限制 |
| **调度器** | `ScanEngine` 创建 `asyncio.Task`，`PhaseManager` 按阶段执行 | 无优先级队列 |
| **任务状态** | `ScanState{status, current_phase, progress}`，存 SQLite | ✅ 已改造: `[TaskState]` 日志追踪 |
| **卡死检测** | `HeartbeatMonitor.cleanup_stuck_tasks(timeout=300s)` | 5秒心跳周期 |

**扫描引擎核心** ([scan_engine.py](file:///Users/yeyuchen002/Downloads/strix/trix/engine/scan_engine.py#L236)):
```python
async def start_scan(self, config: ScanConfig) -> str:
    scan_id = config.scan_id or str(uuid.uuid4())[:8]
    state = ScanState(scan_id=scan_id, config=config)
    phase_manager = PhaseManager(self._registry, self._event_bus)
    
    # 创建异步任务
    task = asyncio.create_task(self._run_scan(scan_id))
    self._tasks[scan_id] = task
    return scan_id

async def _run_scan(self, scan_id: str):
    async for result in phase_manager.execute_all(target, scan_id, phases):
        collector.add_findings(result.findings)
        db.add_phase_result(...)
```

---

## 4. 📝 Critical Code Dump

### 4.1 入口/API层 — app.py

```python
# trix/server/app.py (完整)
"""FastAPI Application."""
import asyncio
import logging
import traceback
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from trix.storage import get_database
from trix.plugins import PluginRegistry
from trix.engine import ScanEngine, EventBus

logger = logging.getLogger(__name__)

# Global instances
_event_bus: EventBus | None = None
_plugin_registry: PluginRegistry | None = None
_scan_engine: ScanEngine | None = None

def get_event_bus() -> EventBus:
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus

def get_plugin_registry() -> PluginRegistry:
    global _plugin_registry
    if _plugin_registry is None:
        _plugin_registry = PluginRegistry()
    return _plugin_registry

def get_scan_engine() -> ScanEngine:
    global _scan_engine
    if _scan_engine is None:
        _scan_engine = ScanEngine(
            plugin_registry=get_plugin_registry(),
            event_bus=get_event_bus(),
        )
    return _scan_engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Trix server...")
    
    db = get_database()
    logger.info(f"Database ready at {db.db_path}")
    
    # Initialize plugin registry (安全模式: 不会崩溃)
    try:
        registry = get_plugin_registry()
        await registry.initialize()  # 返回 PluginLoadResult
        logger.info(f"Loaded {len(registry.list_plugins())} plugins")
    except Exception as e:
        logger.warning(f"Plugin initialization failed: {e}")
    
    yield
    logger.info("Shutting down Trix server...")

def create_app() -> FastAPI:
    app = FastAPI(
        title="Trix Security Scanner",
        version="2.0.0",
        lifespan=lifespan,
    )
    
    # CORS for desktop app
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 🔥 全局异常转换器 (已改造)
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled error: {exc}")
        
        error_response = {
            "status": "error",
            "code": 500,
            "message": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "path": str(request.url.path),
        }
        
        # 通过 EventBus 推送错误到前端
        try:
            from trix.engine.event_bus import Event, EventType
            await get_event_bus().publish(Event(type=EventType.ERROR, data=error_response))
        except Exception:
            pass
        
        return JSONResponse(status_code=500, content=error_response)
    
    # Register routes
    from trix.server.routes import scans, plugins, results, websocket, settings
    app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    app.include_router(plugins.router, prefix="/api/plugins", tags=["plugins"])
    app.include_router(websocket.router, prefix="/ws", tags=["websocket"])
    
    return app

app = create_app()
```

---

### 4.2 核心调度器 — scan_engine.py (核心片段)

```python
# trix/engine/scan_engine.py

class ScanEngine:
    """Main scan engine that orchestrates security assessments."""
    
    def __init__(self, plugin_registry, event_bus):
        self._registry = plugin_registry
        self._event_bus = event_bus
        self._scans: dict[str, ScanState] = {}
        self._tasks: dict[str, asyncio.Task] = {}
    
    async def start_scan(self, config: ScanConfig) -> str:
        scan_id = config.scan_id or str(uuid.uuid4())[:8]
        
        state = ScanState(scan_id=scan_id, config=config, status=ScanStatus.PENDING)
        self._scans[scan_id] = state
        
        phase_manager = PhaseManager(self._registry, self._event_bus)
        
        # 创建异步任务
        task = asyncio.create_task(self._run_scan(scan_id))
        self._tasks[scan_id] = task
        
        return scan_id
    
    async def _run_scan(self, scan_id: str):
        state = self._scans[scan_id]
        state.status = ScanStatus.RUNNING
        
        await self._event_bus.publish(Event(
            type=EventType.SCAN_STARTED,
            scan_id=scan_id,
            data={"target": config.target},
        ))
        
        try:
            async for result in phase_manager.execute_all(target, scan_id, phases):
                collector.add_findings(result.findings)
                db.add_vulnerability(...)  # 持久化
                
            state.status = ScanStatus.COMPLETED
            await self._event_bus.publish(Event(type=EventType.SCAN_COMPLETED, ...))
            
        except Exception as e:
            state.status = ScanStatus.FAILED
            await self._event_bus.publish(Event(type=EventType.SCAN_FAILED, data={"error": str(e)}))
```

---

### 4.3 插件基类 — base.py (核心接口)

```python
# trix/plugins/base.py

class BasePlugin(ABC):
    """Abstract base class for all Trix plugins."""
    
    # 必需类属性
    name: str
    version: str
    phases: list[ScanPhase]
    capabilities: list[PluginCapability]
    
    @abstractmethod
    async def check_installed(self) -> tuple[bool, str]:
        """检查工具是否已安装."""
        raise NotImplementedError
    
    @abstractmethod
    async def install(self) -> tuple[bool, str]:
        """安装工具."""
        raise NotImplementedError
    
    @abstractmethod
    async def execute(
        self, target: str, phase: ScanPhase, parameters: dict
    ) -> AsyncIterator[PluginEvent]:
        """执行插件，yield 事件流."""
        raise NotImplementedError
        yield
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> list[VulnerabilityFinding]:
        """解析工具原始输出."""
        raise NotImplementedError
    
    # Helper: 运行命令
    async def run_command(self, cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode(), stderr.decode()
```

---

### 4.4 插件加载器 — loader.py (动态加载)

```python
# trix/plugins/loader.py

class PluginLoader:
    """Loads plugins from the filesystem using importlib."""
    
    def discover_plugins(self) -> list[str]:
        """扫描 plugins/ 目录，返回插件名列表."""
        plugins = []
        for item in self.builtin_plugins_dir.iterdir():
            if item.is_dir() and (item / "plugin.py").exists():
                plugins.append(item.name)
        return plugins
    
    def load_plugin_class(self, plugin_name: str) -> type[BasePlugin]:
        """动态加载插件类."""
        plugin_path = self._find_plugin_dir(plugin_name) / "plugin.py"
        
        spec = importlib.util.spec_from_file_location(
            f"strix_plugins.{plugin_name}", plugin_path
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)  # ⚠️ 可能抛出任何异常
        
        # 查找 BasePlugin 子类
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                return obj
        
        raise PluginLoadError(f"No BasePlugin subclass found")
```

---

### 4.5 LLM 交互逻辑 — llm.py (核心片段)

```python
# trix/llm/llm.py

class LLM:
    """LLM client with memory compression and caching."""
    
    _pending_requests = 0  # 类级别计数器，用于心跳可见性
    _pending_lock = threading.Lock()
    
    def __init__(self, config: LLMConfig, agent_name: str = None):
        self.config = config
        self.memory_compressor = MemoryCompressor(model_name=config.model_name)
        
        # 加载系统提示词模板 (Jinja2)
        if agent_name:
            self.system_prompt = self.jinja_env.get_template("system_prompt.jinja").render(...)
        else:
            self.system_prompt = "You are a helpful AI assistant."
    
    async def generate(self, conversation_history: list[dict], ...) -> LLMResponse:
        """调用 LLM 生成响应."""
        with LLM._pending_lock:
            LLM._pending_requests += 1
        
        try:
            messages = [{"role": "system", "content": self.system_prompt}]
            
            # 压缩历史消息 (避免 token 超限)
            compressed_history = await self.memory_compressor.compress_history(conversation_history)
            messages.extend(compressed_history)
            
            # 调用 LiteLLM
            response = await self._make_request(messages)
            
            content = response.choices[0].message.content
            tool_invocations = parse_tool_invocations(content)
            
            return LLMResponse(content=content, tool_invocations=tool_invocations)
        finally:
            with LLM._pending_lock:
                LLM._pending_requests -= 1
    
    async def _make_request(self, messages: list[dict]) -> ModelResponse:
        completion_args = {
            "model": self.config.model_name,
            "messages": messages,
            "timeout": self.config.timeout,
        }
        queue = get_global_queue()
        return await queue.make_request(completion_args)  # 使用 litellm.acompletion
```

---

### 4.6 事件/通信系统 — websocket.py (前后端通信)

```python
# trix/server/routes/websocket.py

class ConnectionManager:
    """管理 WebSocket 连接."""
    
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
        self.scan_subscriptions: dict[str, set[str]] = {}  # scan_id -> client_ids
    
    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
    
    async def broadcast_to_scan(self, scan_id: str, message: dict):
        """向订阅特定扫描的客户端广播消息."""
        for client_id in self.scan_subscriptions.get(scan_id, set()):
            await self.send_personal(client_id, message)

manager = ConnectionManager()

def setup_event_bus_handlers():
    """设置 EventBus 事件转发到 WebSocket."""
    event_bus = get_event_bus()
    
    async def handle_vulnerability_found(event: Event):
        scan_id = event.scan_id
        await manager.broadcast_to_scan(scan_id, {
            "type": "vulnerability.found",
            "data": event.data,
        })
    
    async def handle_plugin_error(event: Event):
        # 🔥 插件错误推送给前端
        scan_id = event.scan_id
        await manager.broadcast_to_scan(scan_id, {
            "type": "plugin.error",
            "data": event.data,  # 包含 plugin, error, traceback
        })
    
    event_bus.subscribe(EventType.VULNERABILITY_FOUND, handle_vulnerability_found)
    event_bus.subscribe(EventType.PLUGIN_ERROR, handle_plugin_error)

# WebSocket 端点
@router.websocket("/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("action") == "subscribe":
                manager.subscribe_to_scan(client_id, data["scan_id"])
    except WebSocketDisconnect:
        manager.disconnect(client_id)
```

---

## 5. 🚨 已识别的痛点与改造状态

| 痛点 | 现状 | 改造状态 |
|------|------|----------|
| **插件加载崩溃** | `load_plugin_class()` 异常传播 | ✅ 已改造: `PluginLoadResult{valid, invalid}` |
| **后端报错前端看不到** | 只返回 `500` | ✅ 已改造: 标准化错误 + EventBus 推送 |
| **前后端状态不同步** | WebSocket 已有，但错误事件不全 | ✅ 已添加 `PLUGIN_ERROR` 推送 |
| **AI 漏洞挖掘能力有限** | 仅做判断，不参与规划 | ⚠️ 待增强 |
| **扩展性差** | 单进程 asyncio | ⚠️ 考虑引入 Celery/分布式 |
