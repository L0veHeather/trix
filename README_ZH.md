# 🐯trix (Tiger-Strix)

> **下一代 AI 原生确定性 DAST 扫描引擎**

🐯trix 是一款强大的现代化动态应用安全测试 (DAST) 平台。它用**确定性的阶段化编排逻辑**取代了不可控的 Agent 循环，并利用 **AI 原生反馈闭环 (Feedback Loop)** 实现了对手术刀级别的漏洞检测精度。

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Architecture](https://img.shields.io/badge/architecture-Controller--Brain-orange)
![UI](https://img.shields.io/badge/interface-React%20%7C%20Tauri-cyan)

---

## 🚀 AI 原生革命

Tiger-Strix 的核心哲学是将 AI 视为 **“超级分析师”**，而非黑盒控制器。

- **确定性流程**: 安全阶段（侦察 -> 枚举 -> 扫描 -> 验证）由代码严格控制，确保 100% 的资产覆盖率。
- **AI 反馈闭环**: 当 AI 怀疑存在漏洞但置信度不足时 (50-80%)，它会自动生成变异 Payload 并进行递归验证，直至确认或排除风险。
- **零幻觉**: 每一个漏洞发现都配备原始 HTTP PoC、证据截图和严密的推理过程。

---

## 🛠️ “一键式” 极简体验

告别复杂的配置。Tiger-Strix 旨在实现“原生运行，视觉配置”。

### 1. 启动
```bash
git clone https://github.com/your-repo/trix.git
cd trix
./start.sh
```
*该脚本将自动启动后端引擎 (:8000) 和 Web 管理面板 (:5173)。*

### 2. 通过 UI 配置
无需在终端手动 `export` 环境变量。直接打开 Web UI 并进入 **设置 (Settings)** 页面：
- **选择供应商**: 支持 OpenAI, Anthropic, DeepSeek 以及本地模型 (Ollama/vLLM)。
- **密钥管理**: 在界面中直接输入 API Key，配置将持久化保存到本地数据库中。
- **模型切换**: 随时一键从 `gpt-4o-mini` 切换到 `claude-3-5-sonnet` 或 `deepseek-chat`。

---

## 🎨 Web UI：为安全运营赋能

Tiger-Strix 的仪表盘不仅仅是一个展示窗口，它更是一个**插件 IDE**：

### ⚡ 无代码添加插件
发现了一个新的命令行工具，或者想集成 `nikto`/`nuclei`？
1. 进入 **插件 (Plugins)** 页面。
2. 点击 **添加自定义插件 (Add Custom Plugin)**。
3. 填写命令模板：`nuclei -u {target} -t cves/`
4. 分配扫描阶段（例如：漏洞扫描）。
5. **即刻生效**。AI 大脑将在后续扫描中自动分析该工具的输出。

### 📈 实时工作区
- **代码追踪 (Tracer)**: 实时观察 AI 的内部推理逻辑和思考过程。
- **漏洞卡片**: 点击任意漏洞即可查看原始请求/响应、漏洞风险分析及修复建议。
- **动态任务队列**: 实时查看当前正在测试的参数、路径和 Payload。

---

## 🔌 开发者扩展 (低代码)

对于需要深度集成的功能，可以通过继承 `BaseVulnPlugin` 编写 Python 原生插件。

```python
# trix/plugins/vulns/custom_xss.py
from trix.plugins.vulns import BaseVulnPlugin, PayloadContext, PayloadSpec

class CustomXSS(BaseVulnPlugin):
    name = "xss_advanced"
    vuln_type = "xss"

    def generate_payloads(self, context: PayloadContext) -> list[PayloadSpec]:
        """插件只负责生成测试用例；AI 大脑负责最终审计。"""
        return [PayloadSpec(payload="<svg/onload=alert(1)>", description="SVG vector")]
```

---

## 🔍 检测流水线与底层工具

Tiger-Strix 编排了一个多层级的安全流水线。虽然 **AI 大脑** 负责“思考和判定”，但底层依然使用业界顶尖的工具进行“繁重作业”。

### 1. 漏洞发现工作流
1.  **阶段 1: AI 增强型侦察 (Recon)**: 使用 `urlfinder` 进行深度端点发现。随后，Trix 通过 **AI API 分析** 推断隐藏的 API 结构（例如，基于 `/api/v1/user` 推测 `/api/v1/admin` 的存在）。
2.  **阶段 2: 智能敏感信息分析**: 不同于简单的正则匹配，Trix 结合启发式算法与 **LLM 判定**，对发现的 URL 进行深度分析，识别敏感信息泄露（密钥、令牌、配置等）。
3.  **阶段 3: 针对性 Payload 生成**: 漏洞插件（如 `sqli_detector`, `idor_detector`）根据探测到的技术栈和识别出的具体参数，生成定制化的测试 Payload。
4.  **阶段 4: AI 智能审计 (Audit)**: 所有 HTTP 响应都会由 **LLM Judge** 进行审计。它会分析响应头、状态码以及 DOM 结构的细微变化，以识别 Blind SQLi 或 IDOR 等隐蔽漏洞。
5.  **阶段 5: 自主反馈闭环**: 当发现置信度在 50-80% 之间的疑似漏洞时，**递归反馈环** 会自动生成并执行验证任务，进行多轮确认。

### 2. 核心底层集成
Tiger-Strix 精选并深度集成了以下高性能工具：
- **URLFinder-x**: 深度端点发现，支持从 JS、HTML 及 API 响应中提取链接。
- **Nuclei**: 基于模板的高级已知漏洞 (CVE) 及配置缺陷扫描。
- **Katana / HTTPX**: 业界领先的资产探测与自动化爬虫引擎。
- **AI 驱动逻辑**: 内置专门的 LLM Agent 负责参数预测、WAF 绕过及漏洞最终审计。

---

## 🏗️ 技术架构

- **`trix/core/`**: 扫描控制器 (确定性逻辑与高并发控制)。
- **`trix/brain/`**: AI 判定层与重试机制。
- **`trix/server/`**: 基于 FastAPI 的后端，支持 WebSocket 实时进度推送。
- **`desktop/`**: 现代化的 React + Tailwind 前端。

---

## 📄 许可证
Apache 2.0
