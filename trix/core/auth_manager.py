"""Authentication Manager for Multi-User Session Management.

Supports privilege escalation detection by managing multiple user sessions
(e.g., victim/attacker, admin/user) for comparative testing.

Example:
    manager = get_auth_manager()
    
    # Register user sessions
    manager.add_profile(AuthProfile(
        name="victim",
        role="user",
        cookies={"session": "user123-token"},
    ))
    manager.add_profile(AuthProfile(
        name="attacker", 
        role="user",
        cookies={"session": "user456-token"},
    ))
    
    # Get profile for request injection
    victim = manager.get_profile("victim")
    request.headers.update(victim.headers)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from enum import Enum

logger = logging.getLogger(__name__)


class AuthRole(str, Enum):
    """Standard authentication roles."""
    
    ANONYMOUS = "anonymous"     # No auth
    USER = "user"               # Regular user
    ADMIN = "admin"             # Administrator
    VICTIM = "victim"           # Target user (for IDOR tests)
    ATTACKER = "attacker"       # Attacker trying to access victim's resources
    PRIVILEGED = "privileged"   # Higher privilege level


@dataclass
class AuthProfile:
    """Authentication profile representing a user session.
    
    Contains all credentials needed to authenticate requests as this user.
    
    Attributes:
        name: Unique identifier for this profile (e.g., "victim", "admin")
        role: Role type for categorization
        headers: HTTP headers to inject (e.g., Authorization)
        cookies: Cookies to inject (e.g., session tokens)
        user_id: Associated user ID if known
        metadata: Additional profile metadata
    """
    
    name: str
    role: AuthRole = AuthRole.USER
    
    # Authentication credentials
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    
    # User identity
    user_id: str | None = None
    email: str | None = None
    
    # Additional context
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "role": self.role.value,
            "headers": self.headers,
            "cookies": self.cookies,
            "user_id": self.user_id,
            "email": self.email,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthProfile:
        """Create from dictionary."""
        return cls(
            name=data["name"],
            role=AuthRole(data.get("role", "user")),
            headers=data.get("headers", {}),
            cookies=data.get("cookies", {}),
            user_id=data.get("user_id"),
            email=data.get("email"),
            metadata=data.get("metadata", {}),
        )
    
    def get_cookie_header(self) -> str:
        """Get Cookie header value from cookies dict."""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())
    
    def apply_to_request(self, headers: dict[str, str]) -> dict[str, str]:
        """Apply this profile's auth to request headers.
        
        Returns a new headers dict with auth applied.
        """
        new_headers = headers.copy()
        
        # Add authorization headers
        new_headers.update(self.headers)
        
        # Add cookies
        if self.cookies:
            existing_cookies = new_headers.get("Cookie", "")
            new_cookies = self.get_cookie_header()
            if existing_cookies:
                new_headers["Cookie"] = f"{existing_cookies}; {new_cookies}"
            else:
                new_headers["Cookie"] = new_cookies
        
        return new_headers


class AuthManager:
    """Singleton manager for authentication profiles.
    
    Manages multiple user sessions for privilege escalation testing.
    
    Example:
        manager = get_auth_manager()
        manager.add_profile(AuthProfile(name="victim", ...))
        manager.add_profile(AuthProfile(name="attacker", ...))
        
        # Get profiles for IDOR testing
        victim = manager.get_profile("victim")
        attacker = manager.get_profile("attacker")
    """
    
    def __init__(self):
        self._profiles: dict[str, AuthProfile] = {}
        
        # Add default anonymous profile
        self._profiles["anonymous"] = AuthProfile(
            name="anonymous",
            role=AuthRole.ANONYMOUS,
        )
    
    def add_profile(self, profile: AuthProfile) -> None:
        """Add or update an authentication profile."""
        self._profiles[profile.name] = profile
        logger.info(
            f"[AuthManager] Added profile: {profile.name} "
            f"(role={profile.role.value}, user_id={profile.user_id})"
        )
    
    def get_profile(self, name: str) -> AuthProfile | None:
        """Get a profile by name."""
        return self._profiles.get(name)
    
    def get_profile_or_anonymous(self, name: str | None) -> AuthProfile:
        """Get a profile by name, or return anonymous if not found."""
        if name is None:
            return self._profiles["anonymous"]
        return self._profiles.get(name, self._profiles["anonymous"])
    
    def remove_profile(self, name: str) -> bool:
        """Remove a profile. Returns True if profile existed."""
        if name == "anonymous":
            return False  # Can't remove default
        return self._profiles.pop(name, None) is not None
    
    def list_profiles(self) -> list[AuthProfile]:
        """List all registered profiles."""
        return list(self._profiles.values())
    
    def get_profiles_by_role(self, role: AuthRole) -> list[AuthProfile]:
        """Get all profiles with a specific role."""
        return [p for p in self._profiles.values() if p.role == role]
    
    def has_multiple_users(self) -> bool:
        """Check if we have at least 2 non-anonymous profiles.
        
        Required for IDOR/privilege escalation testing.
        """
        non_anonymous = [
            p for p in self._profiles.values() 
            if p.role != AuthRole.ANONYMOUS
        ]
        return len(non_anonymous) >= 2
    
    def get_victim_attacker_pair(self) -> tuple[AuthProfile | None, AuthProfile | None]:
        """Get victim and attacker profiles if configured.
        
        Returns:
            Tuple of (victim, attacker) profiles or (None, None)
        """
        victim = self.get_profile("victim")
        attacker = self.get_profile("attacker")
        
        # If not explicitly named, try to find by role
        if victim is None:
            victims = self.get_profiles_by_role(AuthRole.VICTIM)
            victim = victims[0] if victims else None
        
        if attacker is None:
            attackers = self.get_profiles_by_role(AuthRole.ATTACKER)
            attacker = attackers[0] if attackers else None
        
        # As fallback, use any two user profiles
        if victim is None or attacker is None:
            users = self.get_profiles_by_role(AuthRole.USER)
            if len(users) >= 2:
                victim = users[0]
                attacker = users[1]
        
        return victim, attacker
    
    def get_admin_user_pair(self) -> tuple[AuthProfile | None, AuthProfile | None]:
        """Get admin and regular user profiles for vertical privilege testing.
        
        Returns:
            Tuple of (admin, user) profiles or (None, None)
        """
        admins = self.get_profiles_by_role(AuthRole.ADMIN)
        users = self.get_profiles_by_role(AuthRole.USER)
        
        admin = admins[0] if admins else None
        user = users[0] if users else None
        
        return admin, user
    
    def clear(self) -> None:
        """Clear all profiles except anonymous."""
        self._profiles = {
            "anonymous": self._profiles["anonymous"]
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Export all profiles as dictionary."""
        return {
            "profiles": {
                name: profile.to_dict()
                for name, profile in self._profiles.items()
            }
        }


# Global singleton instance
_auth_manager: AuthManager | None = None


def get_auth_manager() -> AuthManager:
    """Get the global auth manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


def reset_auth_manager() -> None:
    """Reset the global auth manager (for testing)."""
    global _auth_manager
    _auth_manager = None
