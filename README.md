# 🐯trix (Tiger-Strix)

> **Next-Generation AI-Native DAST Engine with Deterministic Orchestration**

🐯trix is a powerful, modern dynamic application security testing (DAST) platform. It replaces uncontrollable agent loops with a **deterministic phase-based orchestrator** and leverages an **AI-Native Feedback Loop** for surgical precision in vulnerability detection.

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Architecture](https://img.shields.io/badge/architecture-Controller--Brain-orange)
![UI](https://img.shields.io/badge/interface-React%20%7C%20Tauri-cyan)

---

## 🚀 The AI-Native Revolution

Tiger-Strix is built on the philosophy that AI should be a **Super Analyst**, not a black-box controller.

- **Deterministic Flow**: Security phases (Recon -> Enum -> Scan -> Verify) are controlled by code, ensuring 100% coverage.
- **AI Feedback Loop**: When the AI suspects a vulnerability (50-80% confidence), it autonomously generates and tests mutations to confirm or reject findings.
- **Zero Hallucination**: Every finding comes with a raw HTTP PoC and grounded reasoning.

---

## 🛠️ One-Click Experience

Forget complex setup. Tiger-Strix is designed to run natively and configure visually.

### 1. Launch
```bash
git clone https://github.com/your-repo/trix.git
cd trix
./start.sh
```
*This starts the Backend Engine (:8000) and the Web Dashboard (:5173) automatically.*

### 2. Configure via UI
No need to manually `export` environment variables. Open the Web UI and go to **Settings**:
- **Select Provider**: Choose from OpenAI, Anthropic, DeepSeek, or local models (Ollama/vLLM).
- **Manage Keys**: Enter your API keys directly in the dashboard. Settings are persisted in the local database.
- **Pick your Model**: Instantly switch between models like `gpt-4o-mini`, `claude-3-5-sonnet`, or `deepseek-chat`.

---

## 🎨 Web UI: No-Code Power for Security Ops

The Tiger-Strix dashboard is more than a display—it's a **Plugin IDE**:

### ⚡ Add Tools via UI (No Code)
Found a new CLI scanner or want to integrate `nikto`/`nuclei`?
1. Navigate to the **Plugins** page.
2. Click **Add Custom Plugin**.
3. Fill in the command template: `nuclei -u {target} -t cves/`
4. Assign it to a phase (e.g., Vulnerability Scan).
5. **Done.** The AI Brain will now automatically analyze its output during subsequent scans.

### 📈 Real-time Workspace
- **Tracer Logs**: Watch the AI's internal reasoning process in real-time.
- **Vulnerability Cards**: Click any finding to see the raw request/response, risk analysis, and remediation steps.
- **Dynamic Task Queue**: See exactly which parameters and paths are currently being tested.

---

## 🔌 Developer Extension (Low Code)

For deep integration, write Python-native plugins by inheriting `BaseVulnPlugin`.

```python
# trix/plugins/vulns/custom_xss.py
from trix.plugins.vulns import BaseVulnPlugin, PayloadContext, PayloadSpec

class CustomXSS(BaseVulnPlugin):
    name = "xss_advanced"
    vuln_type = "xss"

    def generate_payloads(self, context: PayloadContext) -> list[PayloadSpec]:
        """Plugin only generates; AI Brain judges."""
        return [PayloadSpec(payload="<svg/onload=alert(1)>", description="SVG vector")]
```

---

## 🔍 Detection Pipeline & Underlying Tools

Tiger-Strix orchestrates a multi-layered security pipeline. While the **Brain** handles the "thinking", we use industry-standard tools for the "heavy lifting".

### 1. The Detection Workflow
1.  **Node 1: AI-Enhanced Reconnaissance**: `urlfinder` performs deep passive discovery of endpoints. Trix then uses **AI API Analysis** to infer hidden API structures (e.g., predicting `/api/v1/admin` based on `/api/v1/user`).
2.  **Node 2: Intelligent Sensitivity Analysis**: Instead of simple pattern matching, Trix analyzes discovered URLs for sensitive exposures (keys, tokens, configs) using a combination of heuristics and **LLM Judgment**.
3.  **Node 3: Targeted Payload Gen**: Plugins (e.g., `sqli_detector`, `idor_detector`) generate payloads tailored to the detected tech stack and the specific parameters identified.
4.  **Node 4: AI Audit**: Every HTTP response is fed into the **LLM Judge**. It analyzes headers, status codes, and DOM changes to detect subtle vulnerabilities (like Blind SQLi or IDOR).
5.  **Node 5: Autonomous Feedback Loop**: If a potential vulnerability is found with uncertain confidence (50-80%), the **Recursive Feedback Loop** autonomously generates and executes verification tasks.

### 2. Core Integrated Tools
Tiger-Strix focuses on high-precision tools integrated into the AI workflow:
- **URLFinder-x**: Deep endpoint and link discovery from JS, HTML, and API responses.
- **Nuclei**: Advanced template-based scanning for known CVEs and misconfigurations.
- **Katana / HTTPX**: Industry-standard crawling and probing engines.
- **AI-Driven Logic**: Custom LLM agents for parameter guessing, WAF bypass, and vulnerability judgment.

---

## 🏗️ Technical Architecture

- **`trix/core/`**: The `ScanController` (Deterministic logic & Concurrency).
- **`trix/brain/`**: The LLM interface and retry mechanisms.
- **`trix/server/`**: FastAPI backend with WebSocket progress updates.
- **`desktop/`**: Modern React + Tailwind + Vite/Tauri frontend.

---

## 📄 License
Apache 2.0
