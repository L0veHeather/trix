import { useEffect, useRef, useCallback } from "react";
import { useTrixStore, useSettingsStore } from "./store";

type MessageHandler = (data: unknown) => void;

interface WebSocketMessage {
  type: string;
  data?: unknown;
  scan_id?: string;
}

class WebSocketManager {
  private ws: WebSocket | null = null;
  private clientId: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private messageHandlers: Map<string, Set<MessageHandler>> = new Map();
  private subscriptions: Set<string> = new Set();

  constructor() {
    this.clientId = `client-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  connect() {
    const wsUrl = useSettingsStore.getState().wsUrl;
    const url = `${wsUrl}/${this.clientId}`;

    try {
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log("WebSocket connected");
        useTrixStore.getState().setWsConnected(true);
        this.reconnectAttempts = 0;

        // Resubscribe to all scans
        this.subscriptions.forEach((scanId) => {
          this.send({ action: "subscribe", scan_id: scanId });
        });
      };

      this.ws.onclose = () => {
        console.log("WebSocket disconnected");
        useTrixStore.getState().setWsConnected(false);
        this.attemptReconnect();
      };

      this.ws.onerror = (error) => {
        console.error("WebSocket error:", error);
      };

      this.ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          this.handleMessage(message);
        } catch (e) {
          console.error("Failed to parse WebSocket message:", e);
        }
      };
    } catch (error) {
      console.error("Failed to connect WebSocket:", error);
      this.attemptReconnect();
    }
  }

  private attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log("Max reconnect attempts reached");
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    setTimeout(() => this.connect(), delay);
  }

  private handleMessage(message: WebSocketMessage) {
    const { type, data } = message;
    const store = useTrixStore.getState();

    // Call registered handlers
    const handlers = this.messageHandlers.get(type);
    if (handlers) {
      handlers.forEach((handler) => handler(data));
    }

    // Handle built-in message types and add console logs
    switch (type) {
      case "scan.started": {
        const startData = data as { target: string; scan_id: string; phases?: string[] };
        store.addConsoleLog(startData.scan_id, {
          type: "info",
          source: "system",
          message: `🚀 Scan started for target: ${startData.target}`,
          details: startData,
        });
        if (startData.phases) {
          store.addConsoleLog(startData.scan_id, {
            type: "info",
            source: "system",
            message: `📋 Phases: ${startData.phases.join(" → ")}`,
          });
        }
        break;
      }

      case "scan.progress": {
        const progressData = data as { progress: number; phase: string; scan_id: string };
        store.updateScanProgress(progressData.progress, progressData.phase);
        break;
      }

      case "phase.started": {
        const phaseData = data as { phase: string; scan_id: string; plugins?: string[] };
        store.updatePhase(phaseData.phase, { status: "running" });
        store.addConsoleLog(phaseData.scan_id, {
          type: "info",
          source: phaseData.phase,
          message: `▶️ Starting phase: ${formatPhaseName(phaseData.phase)}`,
        });
        if (phaseData.plugins?.length) {
          store.addConsoleLog(phaseData.scan_id, {
            type: "info",
            source: phaseData.phase,
            message: `  Plugins: ${phaseData.plugins.join(", ")}`,
          });
        }
        break;
      }

      case "phase.completed": {
        const completedData = data as { phase: string; findings_count: number; scan_id: string; duration_ms?: number };
        store.updatePhase(completedData.phase, {
          status: "completed",
          findingsCount: completedData.findings_count,
        });
        const duration = completedData.duration_ms ? ` (${(completedData.duration_ms / 1000).toFixed(1)}s)` : "";
        store.addConsoleLog(completedData.scan_id, {
          type: "success",
          source: completedData.phase,
          message: `✅ Phase completed: ${formatPhaseName(completedData.phase)} - ${completedData.findings_count} findings${duration}`,
        });
        break;
      }

      case "plugin.started": {
        const pluginData = data as { plugin: string; scan_id: string; phase?: string };
        store.addConsoleLog(pluginData.scan_id, {
          type: "command",
          source: pluginData.plugin,
          message: `🔧 Running plugin: ${pluginData.plugin}`,
        });
        break;
      }

      case "plugin.output": {
        const outputData = data as { plugin: string; scan_id: string; output: string; line?: string };
        const output = outputData.line || outputData.output;
        if (output?.trim()) {
          store.addConsoleLog(outputData.scan_id, {
            type: "output",
            source: outputData.plugin,
            message: output.trim(),
          });
        }
        break;
      }

      case "plugin.completed": {
        const pluginDone = data as { plugin: string; scan_id: string; findings_count?: number; duration_ms?: number };
        const msg = pluginDone.findings_count !== undefined
          ? `✓ ${pluginDone.plugin} completed - ${pluginDone.findings_count} findings`
          : `✓ ${pluginDone.plugin} completed`;
        store.addConsoleLog(pluginDone.scan_id, {
          type: "success",
          source: pluginDone.plugin,
          message: msg,
        });
        break;
      }

      case "vulnerability.found": {
        const vulnData = data as { severity: string; title: string; url?: string; scan_id: string; plugin?: string };
        // Update vulnerability count
        if (store.activeScan) {
          store.setActiveScan({
            ...store.activeScan,
            vulnerabilityCount: store.activeScan.vulnerabilityCount + 1,
          });
        }
        const severityIcon = getSeverityIcon(vulnData.severity);
        store.addConsoleLog(vulnData.scan_id, {
          type: "warning",
          source: vulnData.plugin || "scanner",
          message: `${severityIcon} [${vulnData.severity.toUpperCase()}] ${vulnData.title}`,
          details: vulnData,
        });
        if (vulnData.url) {
          store.addConsoleLog(vulnData.scan_id, {
            type: "output",
            source: vulnData.plugin || "scanner",
            message: `  └─ ${vulnData.url}`,
          });
        }
        break;
      }

      case "scan.completed": {
        const completeData = data as { scan_id: string; total_findings?: number; duration_ms?: number };
        store.updateScanStatus("completed");
        const duration = completeData.duration_ms ? `in ${(completeData.duration_ms / 1000).toFixed(1)}s` : "";
        store.addConsoleLog(completeData.scan_id, {
          type: "success",
          source: "system",
          message: `🎉 Scan completed ${duration}`,
        });
        if (completeData.total_findings !== undefined) {
          store.addConsoleLog(completeData.scan_id, {
            type: "info",
            source: "system",
            message: `📊 Total findings: ${completeData.total_findings}`,
          });
        }
        break;
      }

      case "scan.error": {
        const errorData = data as { scan_id: string; error: string; phase?: string; plugin?: string };
        store.addConsoleLog(errorData.scan_id, {
          type: "error",
          source: errorData.plugin || errorData.phase || "system",
          message: `❌ Error: ${errorData.error}`,
          details: errorData,
        });
        break;
      }

      case "scan.failed": {
        const failData = data as { scan_id: string; error: string };
        store.updateScanStatus("failed");
        store.addConsoleLog(failData.scan_id, {
          type: "error",
          source: "system",
          message: `💥 Scan failed: ${failData.error}`,
        });
        break;
      }

      case "llm.request": {
        const llmData = data as { scan_id: string; prompt_type?: string };
        store.addConsoleLog(llmData.scan_id, {
          type: "info",
          source: "llm",
          message: `🤖 LLM request: ${llmData.prompt_type || "analysis"}`,
        });
        break;
      }

      case "llm.response": {
        const llmResp = data as { scan_id: string; summary?: string };
        if (llmResp.summary) {
          store.addConsoleLog(llmResp.scan_id, {
            type: "output",
            source: "llm",
            message: `  └─ ${llmResp.summary}`,
          });
        }
        break;
      }

      case "ai.intervention": {
        const aiData = data as { scan_id: string; message: string; target?: string; plugin?: string };
        store.addConsoleLog(aiData.scan_id, {
          type: "info",
          source: "AI Brain",
          message: `🤖 ${aiData.message}`,
          details: aiData,
        });
        break;
      }

      case "plugin.event": {
        const pEvent = data as { scan_id: string; plugin: string; type: string; message: string; data?: any };
        const typeMap: Record<string, any> = {
          "output": "output",
          "warning": "warning",
          "error": "error",
          "vulnerability": "warning",
          "started": "command",
          "completed": "success"
        };
        store.addConsoleLog(pEvent.scan_id, {
          type: typeMap[pEvent.type] || "info",
          source: pEvent.plugin,
          message: pEvent.message,
          details: pEvent.data
        });
        break;
      }
    }
  }

  send(message: object) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  subscribe(scanId: string) {
    this.subscriptions.add(scanId);
    this.send({ action: "subscribe", scan_id: scanId });
  }

  unsubscribe(scanId: string) {
    this.subscriptions.delete(scanId);
    this.send({ action: "unsubscribe", scan_id: scanId });
  }

  on(type: string, handler: MessageHandler) {
    if (!this.messageHandlers.has(type)) {
      this.messageHandlers.set(type, new Set());
    }
    this.messageHandlers.get(type)!.add(handler);

    // Return cleanup function
    return () => {
      this.messageHandlers.get(type)?.delete(handler);
    };
  }

  disconnect() {
    this.ws?.close();
    this.ws = null;
  }
}

// Helper functions
function formatPhaseName(phase: string): string {
  return phase
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

function getSeverityIcon(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "🔴";
    case "high": return "🟠";
    case "medium": return "🟡";
    case "low": return "🟢";
    default: return "🔵";
  }
}

// Singleton instance
let wsManager: WebSocketManager | null = null;

export function getWebSocketManager(): WebSocketManager {
  if (!wsManager) {
    wsManager = new WebSocketManager();
  }
  return wsManager;
}

// React hook for WebSocket
export function useWebSocket() {
  const wsRef = useRef<WebSocketManager | null>(null);

  useEffect(() => {
    wsRef.current = getWebSocketManager();
    wsRef.current.connect();

    return () => {
      // Don't disconnect on unmount, keep connection alive
    };
  }, []);

  const subscribe = useCallback((scanId: string) => {
    wsRef.current?.subscribe(scanId);
  }, []);

  const unsubscribe = useCallback((scanId: string) => {
    wsRef.current?.unsubscribe(scanId);
  }, []);

  const on = useCallback((type: string, handler: MessageHandler) => {
    return wsRef.current?.on(type, handler) || (() => { });
  }, []);

  return { subscribe, unsubscribe, on };
}
