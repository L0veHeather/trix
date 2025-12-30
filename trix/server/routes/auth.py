"""Authentication Routes - Browser-based Login Assistant.

Provides API endpoints for browser mirroring login:
- Start login session with Playwright
- Stream screenshots for remote viewing
- Detect login success and extract cookies
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from trix.core.login_assistant import get_login_assistant, LoginSessionStatus
from trix.core.auth_manager import get_auth_manager, AuthProfile, AuthRole

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Request/Response Models ====================

class StartLoginRequest(BaseModel):
    """Request to start a login session."""
    
    url: str = Field(..., description="Target login URL")
    profile_name: str = Field("default", description="Name to save the auth profile as")
    headless: bool = Field(True, description="Run browser in headless mode")


class LoginSessionResponse(BaseModel):
    """Response with login session info."""
    
    session_id: str
    target_url: str
    status: str
    current_url: str | None = None
    cookies_count: int = 0
    error: str | None = None


class SendInputRequest(BaseModel):
    """Request to send input to browser."""
    
    action: str = Field(..., description="Action: click, type, key, scroll")
    data: dict[str, Any] = Field(default_factory=dict, description="Action data")


# ==================== Endpoints ====================

@router.post("/start", response_model=LoginSessionResponse)
async def start_login_session(
    request: StartLoginRequest,
    background_tasks: BackgroundTasks,
):
    """Start a new browser-based login session.
    
    Launches a headless browser, navigates to the login URL,
    and prepares for screenshot streaming.
    """
    assistant = get_login_assistant()
    
    try:
        session_id = await assistant.start_login_session(
            url=request.url,
            headless=request.headless,
        )
        
        # Start background task to detect login success
        background_tasks.add_task(assistant.wait_for_login_success, session_id)
        
        session_info = await assistant.get_session_info(session_id)
        
        return LoginSessionResponse(
            session_id=session_id,
            target_url=request.url,
            status=session_info["status"],
            current_url=session_info.get("current_url"),
        )
        
    except Exception as e:
        logger.error(f"Failed to start login session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}/screenshot")
async def get_screenshot(session_id: str):
    """Get current browser screenshot as Base64 PNG.
    
    Poll this endpoint to get live view of the browser.
    """
    assistant = get_login_assistant()
    
    screenshot = await assistant.get_screenshot(session_id)
    if screenshot is None:
        raise HTTPException(status_code=404, detail="Session not found or screenshot failed")
    
    return {
        "session_id": session_id,
        "screenshot": screenshot,  # Base64 PNG
        "format": "png",
    }


@router.get("/{session_id}/stream")
async def stream_screenshots(session_id: str):
    """Stream screenshots as Server-Sent Events.
    
    Provides real-time browser view without polling.
    """
    assistant = get_login_assistant()
    session = assistant.get_session(session_id)
    
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    async def screenshot_generator():
        while True:
            # Check if session still active
            current_session = assistant.get_session(session_id)
            if current_session is None or current_session.status != LoginSessionStatus.RUNNING:
                yield f"data: {{\"status\": \"{current_session.status.value if current_session else 'closed'}\"}}\n\n"
                break
            
            screenshot = await assistant.get_screenshot(session_id)
            if screenshot:
                yield f"data: {{\"screenshot\": \"{screenshot[:100]}...\", \"full_length\": {len(screenshot)}}}\n\n"
            
            await asyncio.sleep(0.5)  # 2 FPS
    
    return StreamingResponse(
        screenshot_generator(),
        media_type="text/event-stream",
    )


@router.get("/{session_id}/status", response_model=LoginSessionResponse)
async def get_login_status(session_id: str):
    """Get current status of a login session.
    
    Check if cookies have been successfully extracted.
    """
    assistant = get_login_assistant()
    session_info = await assistant.get_session_info(session_id)
    
    if session_info is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return LoginSessionResponse(
        session_id=session_id,
        target_url=session_info["target_url"],
        status=session_info["status"],
        current_url=session_info.get("current_url"),
        cookies_count=len(session_info.get("cookies", [])),
        error=session_info.get("error"),
    )


@router.post("/{session_id}/wait")
async def wait_for_login(
    session_id: str,
    profile_name: str = "default",
    timeout: int = 300,
):
    """Wait for login completion and extract cookies.
    
    Blocks until login is detected or timeout.
    On success, cookies are saved to AuthManager as the specified profile.
    """
    assistant = get_login_assistant()
    auth_manager = get_auth_manager()
    
    session = assistant.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    
    try:
        # If already successful (detected by background task), return immediately
        if session.status == LoginSessionStatus.SUCCESS:
            cookies = session.cookies
        else:
            cookies = await assistant.wait_for_login_success(
                session_id,
                timeout_seconds=timeout,
            )
        
        # Convert cookies to AuthProfile format
        cookie_dict = {c["name"]: c["value"] for c in cookies}
        
        # Create and save auth profile
        profile = AuthProfile(
            name=profile_name,
            role=AuthRole.USER,
            cookies=cookie_dict,
        )
        auth_manager.add_profile(profile)
        
        return {
            "status": "success",
            "profile_name": profile_name,
            "cookies_count": len(cookies),
            "cookies": cookies,  # Full cookie details
        }
        
    except TimeoutError as e:
        raise HTTPException(status_code=408, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{session_id}/input")
async def send_input(session_id: str, request: SendInputRequest):
    """Send input to the browser.
    
    Actions:
    - click: {"x": int, "y": int}
    - type: {"text": str}
    - key: {"key": str}  # e.g., "Enter", "Tab"
    - scroll: {"delta_y": int}
    """
    assistant = get_login_assistant()
    
    success = await assistant.send_input(
        session_id,
        request.action,
        request.data,
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Input action failed")
    
    return {"status": "ok", "action": request.action}


@router.post("/{session_id}/cancel")
async def cancel_session(session_id: str):
    """Cancel an active login session."""
    assistant = get_login_assistant()
    
    success = await assistant.cancel_session(session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {"status": "cancelled", "session_id": session_id}


@router.get("/sessions")
async def list_sessions():
    """List all login sessions."""
    assistant = get_login_assistant()
    sessions = assistant.list_sessions()
    
    return {
        "sessions": [s.to_dict() for s in sessions],
        "count": len(sessions),
    }


# ==================== Integration with AuthManager ====================

@router.get("/profiles")
async def list_auth_profiles():
    """List all saved authentication profiles."""
    manager = get_auth_manager()
    profiles = manager.list_profiles()
    
    return {
        "profiles": [p.to_dict() for p in profiles],
        "has_multiple_users": manager.has_multiple_users(),
    }


@router.delete("/profiles/{profile_name}")
async def delete_auth_profile(profile_name: str):
    """Delete an authentication profile."""
    manager = get_auth_manager()
    
    success = manager.remove_profile(profile_name)
    if not success:
        raise HTTPException(status_code=404, detail="Profile not found or cannot be removed")
    
    return {"status": "deleted", "profile_name": profile_name}
