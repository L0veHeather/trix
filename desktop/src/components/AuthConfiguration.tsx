import { useState, useEffect, useRef } from "react";
import {
    ChevronDown,
    ChevronUp,
    Key,
    Monitor,
    Loader2,
    Check,
    X,
    Plus,
    RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface AuthProfile {
    name: string;
    role: string;
    headers: Record<string, string>;
    cookies: Record<string, string>;
}

interface AuthConfigurationProps {
    onAuthChange: (profiles: AuthProfile[]) => void;
}

export default function AuthConfiguration({ onAuthChange }: AuthConfigurationProps) {
    const [isExpanded, setIsExpanded] = useState(false);
    const [activeTab, setActiveTab] = useState<"manual" | "browser">("manual");

    // Manual input state
    const [profiles, setProfiles] = useState<AuthProfile[]>([
        { name: "victim", role: "user", headers: {}, cookies: {} }
    ]);
    const [currentProfile, setCurrentProfile] = useState(0);
    const [cookieInput, setCookieInput] = useState("");
    const [headerInput, setHeaderInput] = useState("");

    // Browser login state
    const [loginUrl, setLoginUrl] = useState("");
    const [sessionId, setSessionId] = useState<string | null>(null);
    const [screenshot, setScreenshot] = useState<string | null>(null);
    const [loginStatus, setLoginStatus] = useState<"idle" | "running" | "success" | "failed">("idle");
    const [isPolling, setIsPolling] = useState(false);
    const pollingRef = useRef<NodeJS.Timeout | null>(null);

    // API base URL
    const API_BASE = "/api/login";

    // Notify parent of changes
    useEffect(() => {
        onAuthChange(profiles);
    }, [profiles, onAuthChange]);

    // Parse cookie string to object
    const parseCookies = (cookieStr: string): Record<string, string> => {
        const cookies: Record<string, string> = {};
        cookieStr.split(";").forEach((pair) => {
            const [key, value] = pair.trim().split("=");
            if (key && value) {
                cookies[key] = value;
            }
        });
        return cookies;
    };

    // Parse header string to object
    const parseHeaders = (headerStr: string): Record<string, string> => {
        const headers: Record<string, string> = {};
        headerStr.split("\n").forEach((line) => {
            const colonIdx = line.indexOf(":");
            if (colonIdx > 0) {
                const key = line.substring(0, colonIdx).trim();
                const value = line.substring(colonIdx + 1).trim();
                if (key && value) {
                    headers[key] = value;
                }
            }
        });
        return headers;
    };

    // Apply manual input to current profile
    const applyManualInput = () => {
        const newProfiles = [...profiles];
        newProfiles[currentProfile] = {
            ...newProfiles[currentProfile],
            cookies: parseCookies(cookieInput),
            headers: parseHeaders(headerInput),
        };
        setProfiles(newProfiles);
    };

    // Add new profile
    const addProfile = () => {
        const newName = profiles.length === 0 ? "victim" :
            profiles.length === 1 ? "attacker" : `user${profiles.length + 1}`;
        setProfiles([...profiles, { name: newName, role: "user", headers: {}, cookies: {} }]);
        setCurrentProfile(profiles.length);
        setCookieInput("");
        setHeaderInput("");
    };

    // Remove profile
    const removeProfile = (index: number) => {
        if (profiles.length <= 1) return;
        const newProfiles = profiles.filter((_, i) => i !== index);
        setProfiles(newProfiles);
        setCurrentProfile(Math.min(currentProfile, newProfiles.length - 1));
    };

    // Start browser login session
    const startBrowserLogin = async () => {
        if (!loginUrl.trim()) return;

        try {
            setLoginStatus("running");
            const response = await fetch(`${API_BASE}/start`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    url: loginUrl,
                    profile_name: profiles[currentProfile]?.name || "default",
                    headless: true,
                }),
            });

            if (!response.ok) throw new Error("Failed to start browser");

            const data = await response.json();
            setSessionId(data.session_id);
            startScreenshotPolling(data.session_id);
        } catch (error) {
            console.error("Browser login failed:", error);
            setLoginStatus("failed");
        }
    };

    // Poll for screenshots
    const startScreenshotPolling = (sid: string) => {
        setIsPolling(true);

        const poll = async () => {
            try {
                // Get screenshot
                const screenshotRes = await fetch(`${API_BASE}/${sid}/screenshot`);
                if (screenshotRes.ok) {
                    const data = await screenshotRes.json();
                    setScreenshot(data.screenshot);
                }

                // Check status
                const statusRes = await fetch(`${API_BASE}/${sid}/status`);
                if (statusRes.ok) {
                    const status = await statusRes.json();

                    if (status.status === "success") {
                        setLoginStatus("success");
                        stopPolling();
                        // Fetch and apply cookies
                        await fetchAndApplyCookies(sid);
                    } else if (status.status === "failed" || status.status === "cancelled") {
                        setLoginStatus("failed");
                        stopPolling();
                    }
                }
            } catch (error) {
                console.error("Polling error:", error);
            }
        };

        pollingRef.current = setInterval(poll, 1000);
        poll(); // Initial call
    };

    const stopPolling = () => {
        if (pollingRef.current) {
            clearInterval(pollingRef.current);
            pollingRef.current = null;
        }
        setIsPolling(false);
    };

    // Fetch cookies and apply to profile
    const fetchAndApplyCookies = async (sid: string) => {
        try {
            const response = await fetch(`${API_BASE}/${sid}/wait?profile_name=${profiles[currentProfile]?.name || "default"}`, {
                method: "POST",
            });

            if (response.ok) {
                const data = await response.json();

                // Convert cookies array to dict
                const cookieDict: Record<string, string> = {};
                (data.cookies || []).forEach((c: { name: string; value: string }) => {
                    cookieDict[c.name] = c.value;
                });

                // Update profile
                const newProfiles = [...profiles];
                newProfiles[currentProfile] = {
                    ...newProfiles[currentProfile],
                    cookies: cookieDict,
                };
                setProfiles(newProfiles);

                // Update UI
                const cookieStr = Object.entries(cookieDict)
                    .map(([k, v]) => `${k}=${v}`)
                    .join("; ");
                setCookieInput(cookieStr);

                // Switch to manual tab to show result
                setActiveTab("manual");
            }
        } catch (error) {
            console.error("Failed to fetch cookies:", error);
        }
    };

    // Cancel browser session
    const cancelBrowserLogin = async () => {
        if (sessionId) {
            try {
                await fetch(`${API_BASE}/${sessionId}/cancel`, { method: "POST" });
            } catch (error) {
                console.error("Cancel failed:", error);
            }
        }
        stopPolling();
        setSessionId(null);
        setScreenshot(null);
        setLoginStatus("idle");
    };

    // Cleanup on unmount
    useEffect(() => {
        return () => {
            stopPolling();
        };
    }, []);

    return (
        <Card className="border-dashed">
            {/* Accordion Header */}
            <CardHeader
                className="cursor-pointer hover:bg-accent/50 transition-colors"
                onClick={() => setIsExpanded(!isExpanded)}
            >
                <CardTitle className="flex items-center justify-between">
                    <span className="flex items-center gap-2 text-base">
                        <Key className="h-4 w-4" />
                        身份配置
                        {profiles.some(p => Object.keys(p.cookies).length > 0) && (
                            <Badge variant="secondary" className="ml-2">
                                已配置
                            </Badge>
                        )}
                    </span>
                    {isExpanded ? (
                        <ChevronUp className="h-4 w-4" />
                    ) : (
                        <ChevronDown className="h-4 w-4" />
                    )}
                </CardTitle>
            </CardHeader>

            {/* Expanded Content */}
            {isExpanded && (
                <CardContent className="space-y-4 pt-0">
                    {/* Profile Tabs */}
                    <div className="flex items-center gap-2 flex-wrap">
                        {profiles.map((profile, idx) => (
                            <div key={idx} className="flex items-center">
                                <Button
                                    variant={currentProfile === idx ? "default" : "outline"}
                                    size="sm"
                                    onClick={() => {
                                        setCurrentProfile(idx);
                                        const cookies = Object.entries(profile.cookies)
                                            .map(([k, v]) => `${k}=${v}`)
                                            .join("; ");
                                        const headers = Object.entries(profile.headers)
                                            .map(([k, v]) => `${k}: ${v}`)
                                            .join("\n");
                                        setCookieInput(cookies);
                                        setHeaderInput(headers);
                                    }}
                                >
                                    {profile.name}
                                    {Object.keys(profile.cookies).length > 0 && (
                                        <Check className="ml-1 h-3 w-3" />
                                    )}
                                </Button>
                                {profiles.length > 1 && (
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        className="h-8 w-8 p-0 ml-1"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            removeProfile(idx);
                                        }}
                                    >
                                        <X className="h-3 w-3" />
                                    </Button>
                                )}
                            </div>
                        ))}
                        <Button variant="outline" size="sm" onClick={addProfile}>
                            <Plus className="h-3 w-3 mr-1" />
                            添加
                        </Button>
                    </div>

                    {/* Tab Switcher */}
                    <div className="flex gap-2 border-b">
                        <button
                            className={cn(
                                "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                                activeTab === "manual"
                                    ? "border-primary text-primary"
                                    : "border-transparent text-muted-foreground hover:text-foreground"
                            )}
                            onClick={() => setActiveTab("manual")}
                        >
                            手动输入
                        </button>
                        <button
                            className={cn(
                                "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                                activeTab === "browser"
                                    ? "border-primary text-primary"
                                    : "border-transparent text-muted-foreground hover:text-foreground"
                            )}
                            onClick={() => setActiveTab("browser")}
                        >
                            <Monitor className="h-4 w-4 inline mr-1" />
                            交互登录
                        </button>
                    </div>

                    {/* Manual Input Tab */}
                    {activeTab === "manual" && (
                        <div className="space-y-4">
                            {/* Cookie Input */}
                            <div className="space-y-2">
                                <label className="text-sm font-medium">Cookie</label>
                                <Input
                                    placeholder="session=abc123; token=xyz789"
                                    value={cookieInput}
                                    onChange={(e) => setCookieInput(e.target.value)}
                                    onBlur={applyManualInput}
                                />
                                <p className="text-xs text-muted-foreground">
                                    格式: name1=value1; name2=value2
                                </p>
                            </div>

                            {/* Header Input */}
                            <div className="space-y-2">
                                <label className="text-sm font-medium">Authorization Headers</label>
                                <textarea
                                    className="w-full h-20 p-3 rounded-md border bg-background text-sm font-mono"
                                    placeholder="Authorization: Bearer eyJ..."
                                    value={headerInput}
                                    onChange={(e) => setHeaderInput(e.target.value)}
                                    onBlur={applyManualInput}
                                />
                                <p className="text-xs text-muted-foreground">
                                    格式: Header-Name: Header-Value (每行一个)
                                </p>
                            </div>
                        </div>
                    )}

                    {/* Browser Login Tab */}
                    {activeTab === "browser" && (
                        <div className="space-y-4">
                            {/* Login URL Input */}
                            <div className="space-y-2">
                                <label className="text-sm font-medium">登录页面 URL</label>
                                <div className="flex gap-2">
                                    <Input
                                        placeholder="https://target.com/login"
                                        value={loginUrl}
                                        onChange={(e) => setLoginUrl(e.target.value)}
                                        disabled={loginStatus === "running"}
                                    />
                                    {loginStatus === "idle" || loginStatus === "failed" ? (
                                        <Button onClick={startBrowserLogin} disabled={!loginUrl.trim()}>
                                            <Monitor className="h-4 w-4 mr-1" />
                                            启动浏览器
                                        </Button>
                                    ) : (
                                        <Button variant="destructive" onClick={cancelBrowserLogin}>
                                            <X className="h-4 w-4 mr-1" />
                                            取消
                                        </Button>
                                    )}
                                </div>
                            </div>

                            {/* Status Indicator */}
                            {loginStatus !== "idle" && (
                                <div className="flex items-center gap-2">
                                    {loginStatus === "running" && (
                                        <>
                                            <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
                                            <span className="text-sm">等待登录...</span>
                                        </>
                                    )}
                                    {loginStatus === "success" && (
                                        <>
                                            <Check className="h-4 w-4 text-green-500" />
                                            <span className="text-sm text-green-500">登录成功! Cookie 已提取</span>
                                        </>
                                    )}
                                    {loginStatus === "failed" && (
                                        <>
                                            <X className="h-4 w-4 text-red-500" />
                                            <span className="text-sm text-red-500">登录失败或超时</span>
                                        </>
                                    )}
                                </div>
                            )}

                            {/* Screenshot Display */}
                            {screenshot && (
                                <div className="relative border rounded-lg overflow-hidden bg-black">
                                    <img
                                        src={`data:image/png;base64,${screenshot}`}
                                        alt="Browser screenshot"
                                        className="w-full h-auto"
                                    />
                                    {isPolling && (
                                        <div className="absolute top-2 right-2 flex items-center gap-1 bg-black/50 text-white text-xs px-2 py-1 rounded">
                                            <RefreshCw className="h-3 w-3 animate-spin" />
                                            实时更新
                                        </div>
                                    )}
                                </div>
                            )}

                            {!screenshot && loginStatus === "idle" && (
                                <div className="border-2 border-dashed rounded-lg p-8 text-center text-muted-foreground">
                                    <Monitor className="h-12 w-12 mx-auto mb-2 opacity-50" />
                                    <p>点击"启动浏览器"开始交互式登录</p>
                                    <p className="text-xs mt-1">适用于扫码登录、验证码等场景</p>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Quick Tips */}
                    <div className="text-xs text-muted-foreground border-t pt-3">
                        <p className="font-medium mb-1">💡 越权检测说明:</p>
                        <p>• 配置两个用户 (victim + attacker) 可启用 IDOR 检测</p>
                        <p>• 系统将对比两个用户访问同一资源的响应差异</p>
                    </div>
                </CardContent>
            )}
        </Card>
    );
}
