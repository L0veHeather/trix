"""Knowledge Graph for API Asset Tracking.

Maintains a real-time graph of discovered API resources and their relationships,
enabling business logic vulnerability detection (IDOR, privilege escalation).

Example:
    User(123) --has_many--> Order(456)
    Order(456) --belongs_to--> User(123)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class ResourceType(str, Enum):
    """Types of API resources."""
    USER = "user"
    ADMIN = "admin"
    ORDER = "order"
    PAYMENT = "payment"
    FILE = "file"
    MESSAGE = "message"
    COMMENT = "comment"
    PRODUCT = "product"
    SESSION = "session"
    UNKNOWN = "unknown"


class RelationType(str, Enum):
    """Types of relationships between resources."""
    HAS_MANY = "has_many"        # User has many Orders
    BELONGS_TO = "belongs_to"    # Order belongs to User
    HAS_ONE = "has_one"          # User has one Profile
    ACCESSES = "accesses"        # User accesses Resource
    ADMIN_OF = "admin_of"        # Admin of Resource


class HttpMethod(str, Enum):
    """HTTP methods indicating operations."""
    GET = "GET"          # Read
    POST = "POST"        # Create
    PUT = "PUT"          # Update
    PATCH = "PATCH"      # Partial update
    DELETE = "DELETE"    # Delete


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint."""
    
    path: str
    method: HttpMethod = HttpMethod.GET
    
    # Extracted info
    resource_type: ResourceType = ResourceType.UNKNOWN
    resource_id_param: str | None = None  # e.g., "user_id", "order_id"
    id_value: str | None = None           # e.g., "123"
    
    # Parent resource (for nested routes)
    parent_type: ResourceType | None = None
    parent_id: str | None = None
    
    # Auth requirements
    requires_auth: bool = True
    requires_admin: bool = False
    
    # IDOR risk score (0-100)
    idor_risk_score: int = 0
    
    def __hash__(self):
        return hash((self.path, self.method))
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method.value,
            "resource_type": self.resource_type.value,
            "resource_id_param": self.resource_id_param,
            "id_value": self.id_value,
            "parent_type": self.parent_type.value if self.parent_type else None,
            "parent_id": self.parent_id,
            "requires_auth": self.requires_auth,
            "requires_admin": self.requires_admin,
            "idor_risk_score": self.idor_risk_score,
        }


@dataclass
class Relationship:
    """Relationship between two resources."""
    
    source_type: ResourceType
    source_id: str
    relation: RelationType
    target_type: ResourceType
    target_id: str
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "source": f"{self.source_type.value}:{self.source_id}",
            "relation": self.relation.value,
            "target": f"{self.target_type.value}:{self.target_id}",
        }


# Common patterns for ID extraction
ID_PATTERNS = [
    # UUID
    r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    # Numeric ID
    r'\d+',
    # Alphanumeric ID
    r'[a-zA-Z0-9]{6,}',
]

# Resource type keywords
RESOURCE_KEYWORDS = {
    ResourceType.USER: ['user', 'users', 'profile', 'profiles', 'account', 'accounts', 'member'],
    ResourceType.ADMIN: ['admin', 'admins', 'administrator', 'manage', 'management'],
    ResourceType.ORDER: ['order', 'orders', 'purchase', 'checkout'],
    ResourceType.PAYMENT: ['payment', 'payments', 'billing', 'invoice', 'transaction'],
    ResourceType.FILE: ['file', 'files', 'upload', 'uploads', 'document', 'attachment'],
    ResourceType.MESSAGE: ['message', 'messages', 'chat', 'notification', 'inbox'],
    ResourceType.COMMENT: ['comment', 'comments', 'review', 'feedback'],
    ResourceType.PRODUCT: ['product', 'products', 'item', 'items', 'catalog'],
    ResourceType.SESSION: ['session', 'sessions', 'token', 'auth'],
}


class KnowledgeGraph:
    """Real-time knowledge graph of API structure.
    
    Tracks resources, relationships, and identifies IDOR-prone endpoints.
    
    Example:
        graph = KnowledgeGraph()
        graph.add_endpoint("/api/users/123/orders/456")
        graph.analyze_idor_risks()
        high_risk = graph.get_high_risk_endpoints()
    """
    
    def __init__(self):
        self._endpoints: dict[str, APIEndpoint] = {}  # path -> endpoint
        self._relationships: list[Relationship] = []
        self._resource_ids: dict[ResourceType, set[str]] = defaultdict(set)
        self._path_patterns: dict[str, list[APIEndpoint]] = defaultdict(list)
    
    def add_endpoint(
        self,
        path: str,
        method: str = "GET",
    ) -> APIEndpoint:
        """Add a discovered endpoint to the graph.
        
        Parses the path to extract resources and IDs.
        """
        endpoint = self._parse_endpoint(path, HttpMethod(method.upper()))
        
        key = f"{method}:{path}"
        self._endpoints[key] = endpoint
        
        # Track resource IDs
        if endpoint.id_value:
            self._resource_ids[endpoint.resource_type].add(endpoint.id_value)
        if endpoint.parent_id and endpoint.parent_type:
            self._resource_ids[endpoint.parent_type].add(endpoint.parent_id)
        
        # Build relationships
        if endpoint.parent_type and endpoint.parent_id:
            self._relationships.append(Relationship(
                source_type=endpoint.parent_type,
                source_id=endpoint.parent_id,
                relation=RelationType.HAS_MANY,
                target_type=endpoint.resource_type,
                target_id=endpoint.id_value or "*",
            ))
        
        # Track pattern
        pattern = self._get_path_pattern(path)
        self._path_patterns[pattern].append(endpoint)
        
        logger.debug(f"[KG] Added endpoint: {method} {path} -> {endpoint.resource_type.value}")
        return endpoint
    
    def _parse_endpoint(self, path: str, method: HttpMethod) -> APIEndpoint:
        """Parse a path to extract resource info."""
        endpoint = APIEndpoint(path=path, method=method)
        
        # Split path into segments
        segments = [s for s in path.split('/') if s and s not in ('api', 'v1', 'v2')]
        
        # Find resource type and IDs
        for i, segment in enumerate(segments):
            # Check if this is a resource name
            resource_type = self._identify_resource_type(segment)
            if resource_type != ResourceType.UNKNOWN:
                endpoint.resource_type = resource_type
                
                # Check if next segment is an ID
                if i + 1 < len(segments):
                    next_seg = segments[i + 1]
                    if self._is_id(next_seg):
                        endpoint.id_value = next_seg
                        endpoint.resource_id_param = f"{segment}_id"
                
                # If we already had a resource, that becomes the parent
                if endpoint.parent_type is None and i > 0:
                    prev_type = self._identify_resource_type(segments[i - 2] if i >= 2 else "")
                    if prev_type != ResourceType.UNKNOWN and i >= 2:
                        endpoint.parent_type = prev_type
                        # Find parent ID
                        if self._is_id(segments[i - 1]):
                            endpoint.parent_id = segments[i - 1]
        
        # Detect admin endpoints
        if 'admin' in path.lower():
            endpoint.requires_admin = True
        
        # Calculate IDOR risk
        endpoint.idor_risk_score = self._calculate_idor_risk(endpoint)
        
        return endpoint
    
    def _identify_resource_type(self, segment: str) -> ResourceType:
        """Identify resource type from path segment."""
        segment_lower = segment.lower()
        for res_type, keywords in RESOURCE_KEYWORDS.items():
            if any(kw in segment_lower for kw in keywords):
                return res_type
        return ResourceType.UNKNOWN
    
    def _is_id(self, segment: str) -> bool:
        """Check if segment looks like an ID."""
        for pattern in ID_PATTERNS:
            if re.fullmatch(pattern, segment, re.IGNORECASE):
                return True
        return False
    
    def _get_path_pattern(self, path: str) -> str:
        """Convert path to pattern (replace IDs with :id)."""
        segments = path.split('/')
        pattern_segments = []
        for seg in segments:
            if self._is_id(seg):
                pattern_segments.append(':id')
            else:
                pattern_segments.append(seg)
        return '/'.join(pattern_segments)
    
    def _calculate_idor_risk(self, endpoint: APIEndpoint) -> int:
        """Calculate IDOR risk score (0-100)."""
        score = 0
        
        # Has numeric/sequential ID
        if endpoint.id_value and endpoint.id_value.isdigit():
            score += 30
        
        # User-owned resource
        if endpoint.resource_type in (ResourceType.USER, ResourceType.ORDER, 
                                       ResourceType.FILE, ResourceType.MESSAGE):
            score += 25
        
        # Modifying operation
        if endpoint.method in (HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE):
            score += 20
        
        # Nested route (potential cross-user access)
        if endpoint.parent_type == ResourceType.USER:
            score += 15
        
        # Non-admin route with sensitive data
        if not endpoint.requires_admin and endpoint.resource_type == ResourceType.PAYMENT:
            score += 10
        
        return min(score, 100)
    
    def get_high_risk_endpoints(self, min_score: int = 50) -> list[APIEndpoint]:
        """Get endpoints with high IDOR risk."""
        return [
            ep for ep in self._endpoints.values()
            if ep.idor_risk_score >= min_score
        ]
    
    def get_all_endpoints(self) -> list[APIEndpoint]:
        """Get all tracked endpoints."""
        return list(self._endpoints.values())
    
    def get_resource_ids(self, resource_type: ResourceType) -> set[str]:
        """Get all discovered IDs for a resource type."""
        return self._resource_ids.get(resource_type, set())
    
    def get_relationships(self) -> list[Relationship]:
        """Get all discovered relationships."""
        return self._relationships
    
    def generate_idor_test_cases(self) -> list[dict[str, Any]]:
        """Generate IDOR test cases for high-risk endpoints.
        
        Returns list of test cases with original and modified IDs.
        """
        test_cases = []
        high_risk = self.get_high_risk_endpoints(min_score=40)
        
        for endpoint in high_risk:
            if not endpoint.id_value:
                continue
            
            # Get other known IDs of the same resource type
            other_ids = self._resource_ids[endpoint.resource_type] - {endpoint.id_value}
            
            # Generate modified paths
            for other_id in list(other_ids)[:3]:  # Limit to 3 alternatives
                test_cases.append({
                    "original_path": endpoint.path,
                    "original_id": endpoint.id_value,
                    "modified_id": other_id,
                    "modified_path": endpoint.path.replace(endpoint.id_value, other_id),
                    "resource_type": endpoint.resource_type.value,
                    "method": endpoint.method.value,
                    "risk_score": endpoint.idor_risk_score,
                    "test_type": "horizontal_privilege_escalation",
                })
            
            # Also try sequential IDs if numeric
            if endpoint.id_value.isdigit():
                original_int = int(endpoint.id_value)
                for offset in [-1, 1, -2, 2]:
                    new_id = str(original_int + offset)
                    if new_id not in other_ids:
                        test_cases.append({
                            "original_path": endpoint.path,
                            "original_id": endpoint.id_value,
                            "modified_id": new_id,
                            "modified_path": endpoint.path.replace(endpoint.id_value, new_id),
                            "resource_type": endpoint.resource_type.value,
                            "method": endpoint.method.value,
                            "risk_score": endpoint.idor_risk_score,
                            "test_type": "sequential_id_enumeration",
                        })
        
        return test_cases
    
    def to_dict(self) -> dict[str, Any]:
        """Export graph as dictionary."""
        return {
            "endpoints": [ep.to_dict() for ep in self._endpoints.values()],
            "relationships": [r.to_dict() for r in self._relationships],
            "resource_ids": {
                rt.value: list(ids) for rt, ids in self._resource_ids.items()
            },
        }


# Global instance
_knowledge_graph: KnowledgeGraph | None = None


def get_knowledge_graph() -> KnowledgeGraph:
    """Get the global knowledge graph instance."""
    global _knowledge_graph
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraph()
    return _knowledge_graph
