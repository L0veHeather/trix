import { useSettingsStore } from "./store";

const getApiUrl = () => useSettingsStore.getState().apiUrl;

// Generic fetch wrapper
async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${getApiUrl()}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(error.detail || error.error || `HTTP ${response.status}`);
  }

  return response.json();
}

// ==================== Scan API ====================

export interface CreateScanRequest {
  target: string;
  name?: string;
  phases?: string[];
  plugins?: string[];
  options?: Record<string, unknown>;
}

export interface ScanResponse {
  id: string;
  name: string | null;
  target: string;
  status: string;
  current_phase: string | null;
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  vulnerability_count: number;
}

export interface ScanListResponse {
  scans: ScanResponse[];
  total: number;
}

export const scanApi = {
  create: (data: CreateScanRequest) =>
    apiFetch<ScanResponse>("/api/scans", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  list: (params?: { status?: string; limit?: number; offset?: number }) =>
    apiFetch<ScanListResponse>(
      `/api/scans?${new URLSearchParams(params as Record<string, string>)}`
    ),

  get: (scanId: string) =>
    apiFetch<ScanResponse>(`/api/scans/${scanId}`),

  getStatus: (scanId: string) =>
    apiFetch<{
      scan_id: string;
      status: string;
      current_phase: string | null;
      progress: number;
      phases: Array<{
        phase: string;
        status: string;
        duration_ms: number;
        findings_count: number;
      }>;
      vulnerabilities: {
        total: number;
        by_severity: Record<string, number>;
      };
    }>(`/api/scans/${scanId}/status`),

  pause: (scanId: string) =>
    apiFetch<{ status: string }>(`/api/scans/${scanId}/pause`, { method: "POST" }),

  resume: (scanId: string) =>
    apiFetch<{ status: string }>(`/api/scans/${scanId}/resume`, { method: "POST" }),

  stop: (scanId: string) =>
    apiFetch<{ status: string }>(`/api/scans/${scanId}/stop`, { method: "POST" }),

  delete: (scanId: string) =>
    apiFetch<{ status: string }>(`/api/scans/${scanId}`, { method: "DELETE" }),
};

// ==================== Plugin API ====================

export interface PluginInfo {
  name: string;
  version: string;
  description: string | null;
  author: string | null;
  phases: string[];
  capabilities: string[];
  status: string;
  installed: boolean;
  enabled: boolean;
}

export interface PluginListResponse {
  plugins: PluginInfo[];
  total: number;
}

export const pluginApi = {
  list: (params?: { phase?: string; installed_only?: boolean; enabled_only?: boolean }) =>
    apiFetch<PluginListResponse>(
      `/api/plugins?${new URLSearchParams(params as Record<string, string>)}`
    ),

  get: (pluginName: string) =>
    apiFetch<PluginInfo & { parameters: Array<{ name: string; description: string; type: string }> }>(
      `/api/plugins/${pluginName}`
    ),

  install: (pluginName: string, force = false) =>
    apiFetch<{ status: string; plugin: string; version: string }>(
      `/api/plugins/${pluginName}/install`,
      {
        method: "POST",
        body: JSON.stringify({ name: pluginName, force }),
      }
    ),

  update: (pluginName: string) =>
    apiFetch<{ status: string }>(`/api/plugins/${pluginName}/update`, { method: "POST" }),

  enable: (pluginName: string) =>
    apiFetch<{ status: string }>(`/api/plugins/${pluginName}/enable`, { method: "POST" }),

  disable: (pluginName: string) =>
    apiFetch<{ status: string }>(`/api/plugins/${pluginName}/disable`, { method: "POST" }),

  configure: (pluginName: string, config: Record<string, unknown>) =>
    apiFetch<{ status: string }>(`/api/plugins/${pluginName}/config`, {
      method: "PUT",
      body: JSON.stringify(config),
    }),
};

// ==================== Results API ====================

export interface VulnerabilityResponse {
  id: string;
  scan_id: string;
  title: string;
  severity: string;
  description: string | null;
  url: string | null;
  plugin_name: string | null;
  phase: string | null;
  verification_status: number;
  discovered_at: string | null;
}

export interface VulnerabilityListResponse {
  vulnerabilities: VulnerabilityResponse[];
  total: number;
  stats: {
    total: number;
    by_severity: Record<string, number>;
    verified: number;
    dismissed: number;
  };
}

export const resultsApi = {
  getScanVulnerabilities: (
    scanId: string,
    params?: {
      severity?: string;
      plugin?: string;
      verified_only?: boolean;
      include_dismissed?: boolean;
    }
  ) =>
    apiFetch<VulnerabilityListResponse>(
      `/api/results/scan/${scanId}/vulnerabilities?${new URLSearchParams(
        params as Record<string, string>
      )}`
    ),

  getVulnerability: (vulnId: string) =>
    apiFetch<VulnerabilityResponse>(`/api/results/vulnerability/${vulnId}`),

  verifyVulnerability: (vulnId: string, status: number, notes?: string) =>
    apiFetch<{ status: string }>(`/api/results/vulnerability/${vulnId}/verify`, {
      method: "POST",
      body: JSON.stringify({ status, notes }),
    }),

  dismissVulnerability: (vulnId: string, notes?: string) =>
    apiFetch<{ status: string }>(`/api/results/vulnerability/${vulnId}/dismiss`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),

  getScanStats: (scanId: string) =>
    apiFetch<{
      scan_id: string;
      target: string;
      status: string;
      duration_ms: number;
      vulnerabilities: {
        total: number;
        by_severity: Record<string, number>;
      };
      phases: Record<string, {
        status: string;
        duration_ms: number;
        findings_count: number;
      }>;
    }>(`/api/results/scan/${scanId}/stats`),

  exportResults: (
    scanId: string,
    format: "json" | "markdown" | "sarif" | "csv"
  ) =>
    fetch(`${getApiUrl()}/api/results/scan/${scanId}/export`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format }),
    }).then((res) => res.blob()),

  getRecentVulnerabilities: (limit = 20) =>
    apiFetch<{ vulnerabilities: VulnerabilityResponse[] }>(
      `/api/results/recent?limit=${limit}`
    ),

  getSeverityBreakdown: () =>
    apiFetch<{ breakdown: Record<string, number>; total: number }>(
      "/api/results/severity-breakdown"
    ),
};

// ==================== Settings API ====================

export interface LLMModel {
  id: string;
  name: string;
  description: string;
}

export interface LLMProvider {
  id: string;
  name: string;
  models: LLMModel[];
  requires_key: boolean;
  key_env?: string;
  default_base?: string;
  supports_custom_base?: boolean;
}

export interface LLMConfig {
  model: string;
  api_key: string | null;
  api_base: string | null;
  timeout: number;
  enable_caching: boolean;
  max_tokens: number | null;
}

export interface LLMConfigResponse {
  config: LLMConfig;
  configured_providers: Record<string, boolean>;
}

export const settingsApi = {
  getProviders: () =>
    apiFetch<{ providers: LLMProvider[] }>("/api/settings/providers"),

  getLLMConfig: () =>
    apiFetch<LLMConfigResponse>("/api/settings/llm"),

  updateLLMConfig: (config: Partial<LLMConfig>) =>
    apiFetch<{ status: string; message: string }>("/api/settings/llm", {
      method: "PUT",
      body: JSON.stringify(config),
    }),

  testLLMConnection: () =>
    apiFetch<{ status: string; model?: string; response?: string; message?: string }>(
      "/api/settings/test-llm",
      { method: "POST" }
    ),

  getAllSettings: () =>
    apiFetch<{
      llm: { model: string; timeout: number; enable_caching: boolean };
      telemetry: { enabled: boolean; langfuse_configured: boolean };
      research: { perplexity_configured: boolean };
    }>("/api/settings"),

  updateSetting: (key: string, value: unknown) =>
    apiFetch<{ status: string; key: string }>(`/api/settings/${key}`, {
      method: "PUT",
      body: JSON.stringify({ value }),
    }),
};
// ==================== Auth API (Login Assistant) ====================

export const authApi = {
  startLogin: (url: string, profileName: string) =>
    apiFetch<any>("/api/login/start", {
      method: "POST",
      body: JSON.stringify({ url, profile_name: profileName, headless: true }),
    }),

  getScreenshot: (sessionId: string) =>
    apiFetch<{ screenshot: string }>("/api/login/" + sessionId + "/screenshot"),

  getStatus: (sessionId: string) =>
    apiFetch<{ status: string; target_url: string; current_url?: string; cookies_count: number; error?: string }>(
      "/api/login/" + sessionId + "/status"
    ),

  waitForLogin: (sessionId: string, profileName: string) =>
    apiFetch<any>(`/api/login/${sessionId}/wait?profile_name=${profileName}`, {
      method: "POST",
    }),

  cancelSession: (sessionId: string) =>
    apiFetch<any>(`/api/login/${sessionId}/cancel`, { method: "POST" }),
};
