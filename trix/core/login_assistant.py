"""Login Assistant - Browser Mirroring for Cookie Extraction.

Provides a "remote desktop" like experience for users to log into
target websites via QR code scanning or manual login.

Features:
- Headless browser with screenshot streaming
- Automatic cookie extraction on login success
- URL/Cookie change detection for login completion
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class LoginSessionStatus(str, Enum):
    """Status of a login session."""
    
    PENDING = "pending"         # Created but not started
    RUNNING = "running"         # Browser active, waiting for login
    SUCCESS = "success"         # Login detected, cookies extracted
    FAILED = "failed"           # Login failed or timeout
    CANCELLED = "cancelled"     # User cancelled


@dataclass
class LoginSession:
    """State of a login session."""
    
    session_id: str
    target_url: str
    status: LoginSessionStatus = LoginSessionStatus.PENDING
    
    # Extracted data
    cookies: list[dict[str, Any]] = field(default_factory=list)
    final_url: str | None = None
    
    # Timing
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    
    # Error info
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "status": self.status.value,
            "cookies": self.cookies,
            "final_url": self.final_url,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
        }


class LoginAssistant:
    """Browser-based login assistant for cookie extraction.
    
    Launches a headless browser, provides screenshot streaming,
    and detects login success to extract cookies.
    
    Example:
        assistant = LoginAssistant()
        session_id = await assistant.start_login_session("https://example.com/login")
        
        # Poll for screenshots
        screenshot = await assistant.get_screenshot(session_id)
        
        # Wait for login
        cookies = await assistant.wait_for_login_success(session_id)
    """
    
    def __init__(self):
        self._sessions: dict[str, LoginSession] = {}
        self._browsers: dict[str, Any] = {}  # session_id -> browser
        self._pages: dict[str, Any] = {}     # session_id -> page
        self._contexts: dict[str, Any] = {}  # session_id -> context
        self._playwright: Any = None
    
    async def _ensure_playwright(self) -> None:
        """Ensure Playwright is initialized."""
        if self._playwright is None:
            try:
                from playwright.async_api import async_playwright
                self._playwright = await async_playwright().start()
                logger.info("[LoginAssistant] Playwright initialized")
            except ImportError:
                raise RuntimeError(
                    "Playwright not installed. Run: pip install playwright && playwright install chromium"
                )
    
    async def start_login_session(
        self,
        url: str,
        session_id: str | None = None,
        headless: bool = True,
    ) -> str:
        """Start a new login session with browser.
        
        Args:
            url: Target login URL
            session_id: Optional custom session ID
            headless: Run browser in headless mode (default True)
            
        Returns:
            Session ID for tracking
        """
        import uuid
        
        await self._ensure_playwright()
        
        # Create session
        if session_id is None:
            session_id = str(uuid.uuid4())[:8]
        
        session = LoginSession(
            session_id=session_id,
            target_url=url,
            status=LoginSessionStatus.RUNNING,
        )
        self._sessions[session_id] = session
        
        # Launch browser
        try:
            browser = await self._playwright.chromium.launch(
                headless=headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                ],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            page = await context.new_page()
            
            # Navigate to login page
            await page.goto(url, wait_until="domcontentloaded")
            
            self._browsers[session_id] = browser
            self._contexts[session_id] = context
            self._pages[session_id] = page
            
            logger.info(f"[LoginAssistant] Started session {session_id} for {url}")
            return session_id
            
        except Exception as e:
            session.status = LoginSessionStatus.FAILED
            session.error = str(e)
            logger.error(f"[LoginAssistant] Failed to start session: {e}")
            raise
    
    async def get_screenshot(self, session_id: str) -> str | None:
        """Get current page screenshot as Base64.
        
        Args:
            session_id: Session ID
            
        Returns:
            Base64-encoded PNG screenshot, or None if session not found
        """
        page = self._pages.get(session_id)
        if page is None:
            return None
        
        try:
            screenshot_bytes = await page.screenshot(type="png")
            return base64.b64encode(screenshot_bytes).decode("utf-8")
        except Exception as e:
            logger.warning(f"[LoginAssistant] Screenshot failed: {e}")
            return None
    
    async def get_session_info(self, session_id: str) -> dict[str, Any] | None:
        """Get current session info including URL."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        
        page = self._pages.get(session_id)
        current_url = page.url if page else None
        
        return {
            **session.to_dict(),
            "current_url": current_url,
        }
    
    async def wait_for_login_success(
        self,
        session_id: str,
        success_indicators: list[str] | None = None,
        cookie_names: list[str] | None = None,
        timeout_seconds: int = 300,
        poll_interval: float = 2.0,
    ) -> list[dict[str, Any]]:
        """Wait for login to complete and extract cookies.
        
        Detection methods:
        1. URL changed from login page
        2. Specific cookies appeared
        3. Success indicator elements present
        
        Args:
            session_id: Session ID
            success_indicators: CSS selectors indicating login success
            cookie_names: Cookie names that indicate logged-in state
            timeout_seconds: Maximum wait time
            poll_interval: Check interval in seconds
            
        Returns:
            List of extracted cookies
        """
        session = self._sessions.get(session_id)
        page = self._pages.get(session_id)
        context = self._contexts.get(session_id)
        
        if not all([session, page, context]):
            raise ValueError(f"Session {session_id} not found")
        
        initial_url = session.target_url
        start_time = asyncio.get_event_loop().time()
        
        # Default success indicators
        if success_indicators is None:
            success_indicators = [
                "[class*='logout']",
                "[class*='user-menu']",
                "[class*='avatar']",
                "[class*='dashboard']",
                "a[href*='logout']",
            ]
        
        # Default cookie names that indicate login
        if cookie_names is None:
            cookie_names = [
                "session", "token", "auth", "jwt", "access_token",
                "sid", "PHPSESSID", "JSESSIONID", "connect.sid",
            ]
        
        logger.info(f"[LoginAssistant] Waiting for login success on {session_id}...")
        
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout_seconds:
                session.status = LoginSessionStatus.FAILED
                session.error = "Login timeout"
                await self._cleanup_session(session_id)
                raise TimeoutError(f"Login timeout after {timeout_seconds}s")
            
            try:
                current_url = page.url
                
                # Check 1: URL changed significantly
                if self._is_login_redirect(initial_url, current_url):
                    logger.info(f"[LoginAssistant] URL changed: {current_url}")
                    return await self._extract_and_complete(session_id)
                
                # Check 2: Auth cookies present
                cookies = await context.cookies()
                for cookie in cookies:
                    name_lower = cookie["name"].lower()
                    if any(cn.lower() in name_lower for cn in cookie_names):
                        logger.info(f"[LoginAssistant] Auth cookie found: {cookie['name']}")
                        return await self._extract_and_complete(session_id)
                
                # Check 3: Success elements present
                for selector in success_indicators:
                    try:
                        element = await page.query_selector(selector)
                        if element:
                            logger.info(f"[LoginAssistant] Success element found: {selector}")
                            return await self._extract_and_complete(session_id)
                    except Exception:
                        pass
                
            except Exception as e:
                logger.warning(f"[LoginAssistant] Check error: {e}")
            
            await asyncio.sleep(poll_interval)
    
    def _is_login_redirect(self, initial: str, current: str) -> bool:
        """Check if URL change indicates successful login redirect."""
        from urllib.parse import urlparse
        
        initial_parsed = urlparse(initial)
        current_parsed = urlparse(current)
        
        # Same domain, different path (not login/signin)
        if initial_parsed.netloc == current_parsed.netloc:
            login_keywords = ["login", "signin", "auth", "sso", "oauth"]
            current_path = current_parsed.path.lower()
            
            # Not on login page anymore
            if not any(kw in current_path for kw in login_keywords):
                # And path actually changed
                if current_parsed.path != initial_parsed.path:
                    return True
        
        return False
    
    async def _extract_and_complete(self, session_id: str) -> list[dict[str, Any]]:
        """Extract cookies and complete session."""
        session = self._sessions[session_id]
        context = self._contexts[session_id]
        page = self._pages[session_id]
        
        # Extract all cookies
        cookies = await context.cookies()
        
        # Convert to standard format
        cookie_list = [
            {
                "name": c["name"],
                "value": c["value"],
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "expires": c.get("expires", -1),
                "httpOnly": c.get("httpOnly", False),
                "secure": c.get("secure", False),
                "sameSite": c.get("sameSite", "Lax"),
            }
            for c in cookies
        ]
        
        # Update session
        session.status = LoginSessionStatus.SUCCESS
        session.cookies = cookie_list
        session.final_url = page.url
        session.completed_at = datetime.now()
        
        logger.info(
            f"[LoginAssistant] Login success! Extracted {len(cookie_list)} cookies"
        )
        
        # Cleanup browser
        await self._cleanup_session(session_id)
        
        return cookie_list
    
    async def _cleanup_session(self, session_id: str) -> None:
        """Clean up browser resources for a session."""
        browser = self._browsers.pop(session_id, None)
        self._pages.pop(session_id, None)
        self._contexts.pop(session_id, None)
        
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
    
    async def cancel_session(self, session_id: str) -> bool:
        """Cancel an active login session."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        
        session.status = LoginSessionStatus.CANCELLED
        session.completed_at = datetime.now()
        
        await self._cleanup_session(session_id)
        return True
    
    async def send_input(
        self,
        session_id: str,
        action: str,
        data: dict[str, Any],
    ) -> bool:
        """Send input to the browser page.
        
        Actions:
        - click: {"x": int, "y": int}
        - type: {"text": str}
        - key: {"key": str}  # e.g., "Enter", "Tab"
        - scroll: {"delta_y": int}
        """
        page = self._pages.get(session_id)
        if page is None:
            return False
        
        try:
            if action == "click":
                await page.mouse.click(data["x"], data["y"])
            elif action == "type":
                await page.keyboard.type(data["text"])
            elif action == "key":
                await page.keyboard.press(data["key"])
            elif action == "scroll":
                await page.mouse.wheel(0, data.get("delta_y", 100))
            else:
                return False
            return True
        except Exception as e:
            logger.warning(f"[LoginAssistant] Input failed: {e}")
            return False
    
    def get_session(self, session_id: str) -> LoginSession | None:
        """Get session by ID."""
        return self._sessions.get(session_id)
    
    def list_sessions(self) -> list[LoginSession]:
        """List all sessions."""
        return list(self._sessions.values())
    
    async def close(self) -> None:
        """Close all sessions and Playwright."""
        for session_id in list(self._browsers.keys()):
            await self._cleanup_session(session_id)
        
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None


# Global instance
_login_assistant: LoginAssistant | None = None


def get_login_assistant() -> LoginAssistant:
    """Get the global login assistant instance."""
    global _login_assistant
    if _login_assistant is None:
        _login_assistant = LoginAssistant()
    return _login_assistant
