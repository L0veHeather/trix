"""HTTP Request and Response models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class HttpRequest:
    """HTTP Request model."""
    
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    params: dict[str, str] = field(default_factory=dict)
    
    # === Payload injection info ===
    injected_parameter: str = ""
    injected_payload: str = ""
    original_value: str = ""
    
    def to_raw(self) -> str:
        """Convert to raw HTTP request string."""
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        
        lines = [f"{self.method} {path} HTTP/1.1"]
        
        # Add host header
        if "Host" not in self.headers:
            lines.append(f"Host: {parsed.netloc}")
        
        # Add other headers
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        
        # Add body
        if self.body:
            if "Content-Length" not in self.headers:
                lines.append(f"Content-Length: {len(self.body)}")
            lines.append("")
            lines.append(self.body)
        
        return "\r\n".join(lines)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "params": self.params,
            "injected_parameter": self.injected_parameter,
            "injected_payload": self.injected_payload,
            "original_value": self.original_value,
        }


@dataclass
class HttpResponse:
    """HTTP Response model."""
    
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    
    # === Timing ===
    response_time_ms: float = 0.0
    
    # === Error info ===
    error: str | None = None
    
    def to_raw(self) -> str:
        """Convert to raw HTTP response string."""
        if self.error:
            return f"ERROR: {self.error}"
        
        lines = [f"HTTP/1.1 {self.status_code}"]
        
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        
        lines.append("")
        lines.append(self.body[:10000])  # Limit body size
        
        return "\r\n".join(lines)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "response_time_ms": self.response_time_ms,
            "error": self.error,
        }
    
    @property
    def is_success(self) -> bool:
        """Check if response is successful (2xx)."""
        return 200 <= self.status_code < 300
    
    @property
    def is_error(self) -> bool:
        """Check if response is error (4xx/5xx)."""
        return self.status_code >= 400


@dataclass
class ScanTarget:
    """Scan target definition."""
    
    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    
    # === Authentication ===
    auth_token: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    
    # === Metadata ===
    name: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)  # Detected technologies
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "headers": self.headers,
            "body_template": self.body_template,
            "auth_token": self.auth_token,
            "cookies": self.cookies,
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
        }
    
    @classmethod
    def from_url(cls, url: str, method: str = "GET") -> "ScanTarget":
        """Create a simple target from URL."""
        return cls(url=url, method=method)
