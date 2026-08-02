"""
Target State Manager for AEGIS security scanner.

This module maintains the global state of the target topology, tracks active sessions,
discovered endpoints, and observed state transitions.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import threading
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class EndpointStatus(Enum):
    """Status of discovered endpoints."""
    UNKNOWN = "unknown"
    ACCESSIBLE = "accessible"
    INACCESSIBLE = "inaccessible"
    AUTHENTICATED = "authenticated"
    VULNERABLE = "vulnerable"
    SAFE = "safe"


@dataclass
class SessionInfo:
    """Information about an active session."""
    session_id: str
    target: str
    protocol: str
    start_time: datetime
    last_activity: datetime
    state: str = "active"
    auth_tokens: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveredEndpoint:
    """Information about a discovered endpoint."""
    path: str
    method: str
    status: EndpointStatus = EndpointStatus.UNKNOWN
    parameters: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    response_codes: Set[int] = field(default_factory=set)
    last_tested: Optional[datetime] = None
    vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateTransition:
    """Information about a state transition."""
    from_state: str
    to_state: str
    trigger: str
    timestamp: datetime
    parameters: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TopologySnapshot:
    """A snapshot of the target topology at a point in time."""
    timestamp: datetime
    endpoints: List[DiscoveredEndpoint]
    sessions: List[SessionInfo]
    state_transitions: List[StateTransition]
    current_state: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetState:
    """The global state of a target."""
    target: str
    base_url: str
    current_state: str = "initial"
    discovered_endpoints: Dict[str, DiscoveredEndpoint] = field(default_factory=dict)
    active_sessions: Dict[str, SessionInfo] = field(default_factory=dict)
    state_transitions: List[StateTransition] = field(default_factory=list)
    global_parameters: Dict[str, Any] = field(default_factory=dict)
    auth_context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)


class TargetStateManager:
    """
    Maintain the global state of the target topology.
    
    Tracks active sessions, discovered endpoints, and observed state transitions.
    Provides thread-safe access to state information and generates topology snapshots.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the target state manager.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.targets: Dict[str, TargetState] = {}
        self.current_target: Optional[str] = None
        
        # Lock for thread-safe operations
        self._lock = threading.RLock()
        
        # Snapshot history
        self.snapshots: List[TopologySnapshot] = field(default_factory=list)
        self.max_snapshots = self.config.get('max_snapshots', 100)
        
        logger.info("TargetStateManager initialized")
    
    def initialize(self):
        """Initialize the state manager."""
        logger.info("TargetStateManager initialized")
    
    def register_target(
        self,
        target: str,
        base_url: str,
        initial_state: str = "initial"
    ) -> TargetState:
        """
        Register a new target for tracking.
        
        Args:
            target: Target identifier
            base_url: Base URL of the target
            initial_state: Initial state identifier
            
        Returns:
            The created TargetState
        """
        with self._lock:
            if target in self.targets:
                logger.warning(f"Target {target} already registered")
                return self.targets[target]
            
            target_state = TargetState(
                target=target,
                base_url=base_url,
                current_state=initial_state
            )
            
            self.targets[target] = target_state
            self.current_target = target
            
            logger.info(f"Registered target: {target}")
            return target_state
    
    def get_target(self, target: str) -> Optional[TargetState]:
        """
        Get the state for a specific target.
        
        Args:
            target: Target identifier
            
        Returns:
            TargetState if found, None otherwise
        """
        with self._lock:
            return self.targets.get(target)
    
    def get_current_target(self) -> Optional[TargetState]:
        """
        Get the current active target state.
        
        Returns:
            TargetState if set, None otherwise
        """
        with self._lock:
            if self.current_target:
                return self.targets.get(self.current_target)
            return None
    
    def set_current_target(self, target: str) -> bool:
        """
        Set the current active target.
        
        Args:
            target: Target identifier
            
        Returns:
            True if successful, False if target not found
        """
        with self._lock:
            if target in self.targets:
                self.current_target = target
                logger.info(f"Current target set to: {target}")
                return True
            return False
    
    def add_endpoint(
        self,
        target: str,
        endpoint: DiscoveredEndpoint
    ) -> bool:
        """
        Add or update a discovered endpoint.
        
        Args:
            target: Target identifier
            endpoint: The endpoint to add
            
        Returns:
            True if added/updated, False if target not found
        """
        with self._lock:
            if target not in self.targets:
                return False
            
            key = f"{endpoint.method}:{endpoint.path}"
            self.targets[target].discovered_endpoints[key] = endpoint
            self.targets[target].last_updated = datetime.now()
            
            logger.debug(f"Added endpoint: {key}")
            return True
    
    def get_endpoint(
        self,
        target: str,
        method: str,
        path: str
    ) -> Optional[DiscoveredEndpoint]:
        """
        Get a specific endpoint.
        
        Args:
            target: Target identifier
            method: HTTP method
            path: Endpoint path
            
        Returns:
            DiscoveredEndpoint if found, None otherwise
        """
        with self._lock:
            if target not in self.targets:
                return None
            
            key = f"{method}:{path}"
            return self.targets[target].discovered_endpoints.get(key)
    
    def get_all_endpoints(self, target: str) -> List[DiscoveredEndpoint]:
        """
        Get all endpoints for a target.
        
        Args:
            target: Target identifier
            
        Returns:
            List of DiscoveredEndpoint
        """
        with self._lock:
            if target not in self.targets:
                return []
            
            return list(self.targets[target].discovered_endpoints.values())
    
    def update_endpoint_status(
        self,
        target: str,
        method: str,
        path: str,
        status: EndpointStatus
    ) -> bool:
        """
        Update the status of an endpoint.
        
        Args:
            target: Target identifier
            method: HTTP method
            path: Endpoint path
            status: New status
            
        Returns:
            True if updated, False if endpoint not found
        """
        with self._lock:
            endpoint = self.get_endpoint(target, method, path)
            if endpoint:
                endpoint.status = status
                endpoint.last_tested = datetime.now()
                self.targets[target].last_updated = datetime.now()
                return True
            return False
    
    def add_session(
        self,
        target: str,
        session: SessionInfo
    ) -> bool:
        """
        Add or update an active session.
        
        Args:
            target: Target identifier
            session: The session to add
            
        Returns:
            True if added/updated, False if target not found
        """
        with self._lock:
            if target not in self.targets:
                return False
            
            self.targets[target].active_sessions[session.session_id] = session
            self.targets[target].last_updated = datetime.now()
            
            logger.debug(f"Added session: {session.session_id}")
            return True
    
    def get_session(
        self,
        target: str,
        session_id: str
    ) -> Optional[SessionInfo]:
        """
        Get a specific session.
        
        Args:
            target: Target identifier
            session_id: Session identifier
            
        Returns:
            SessionInfo if found, None otherwise
        """
        with self._lock:
            if target not in self.targets:
                return None
            
            return self.targets[target].active_sessions.get(session_id)
    
    def get_all_sessions(self, target: str) -> List[SessionInfo]:
        """
        Get all active sessions for a target.
        
        Args:
            target: Target identifier
            
        Returns:
            List of SessionInfo
        """
        with self._lock:
            if target not in self.targets:
                return []
            
            return list(self.targets[target].active_sessions.values())
    
    def remove_session(self, target: str, session_id: str) -> bool:
        """
        Remove a session.
        
        Args:
            target: Target identifier
            session_id: Session identifier
            
        Returns:
            True if removed, False if session not found
        """
        with self._lock:
            if target not in self.targets:
                return False
            
            if session_id in self.targets[target].active_sessions:
                del self.targets[target].active_sessions[session_id]
                self.targets[target].last_updated = datetime.now()
                logger.debug(f"Removed session: {session_id}")
                return True
            return False
    
    def record_state_transition(
        self,
        target: str,
        transition: StateTransition
    ) -> bool:
        """
        Record a state transition.
        
        Args:
            target: Target identifier
            transition: The transition to record
            
        Returns:
            True if recorded, False if target not found
        """
        with self._lock:
            if target not in self.targets:
                return False
            
            self.targets[target].state_transitions.append(transition)
            self.targets[target].current_state = transition.to_state
            self.targets[target].last_updated = datetime.now()
            
            logger.debug(
                f"State transition: {transition.from_state} -> {transition.to_state}"
            )
            return True
    
    def get_state_transitions(
        self,
        target: str,
        limit: Optional[int] = None
    ) -> List[StateTransition]:
        """
        Get state transitions for a target.
        
        Args:
            target: Target identifier
            limit: Optional limit on number of transitions to return
            
        Returns:
            List of StateTransition
        """
        with self._lock:
            if target not in self.targets:
                return []
            
            transitions = self.targets[target].state_transitions
            if limit:
                return transitions[-limit:]
            return transitions
    
    def get_current_state(self, target: str) -> Optional[str]:
        """
        Get the current state of a target.
        
        Args:
            target: Target identifier
            
        Returns:
            Current state string if found, None otherwise
        """
        with self._lock:
            if target not in self.targets:
                return None
            
            return self.targets[target].current_state
    
    def set_global_parameter(
        self,
        target: str,
        key: str,
        value: Any
    ) -> bool:
        """
        Set a global parameter for a target.
        
        Args:
            target: Target identifier
            key: Parameter key
            value: Parameter value
            
        Returns:
            True if set, False if target not found
        """
        with self._lock:
            if target not in self.targets:
                return False
            
            self.targets[target].global_parameters[key] = value
            self.targets[target].last_updated = datetime.now()
            return True
    
    def get_global_parameter(
        self,
        target: str,
        key: str,
        default: Any = None
    ) -> Any:
        """
        Get a global parameter for a target.
        
        Args:
            target: Target identifier
            key: Parameter key
            default: Default value if not found
            
        Returns:
            Parameter value or default
        """
        with self._lock:
            if target not in self.targets:
                return default
            
            return self.targets[target].global_parameters.get(key, default)
    
    def set_auth_context(
        self,
        target: str,
        auth_data: Dict[str, Any]
    ) -> bool:
        """
        Set authentication context for a target.
        
        Args:
            target: Target identifier
            auth_data: Authentication data
            
        Returns:
            True if set, False if target not found
        """
        with self._lock:
            if target not in self.targets:
                return False
            
            self.targets[target].auth_context.update(auth_data)
            self.targets[target].last_updated = datetime.now()
            return True
    
    def get_auth_context(self, target: str) -> Dict[str, Any]:
        """
        Get authentication context for a target.
        
        Args:
            target: Target identifier
            
        Returns:
            Authentication context dictionary
        """
        with self._lock:
            if target not in self.targets:
                return {}
            
            return self.targets[target].auth_context.copy()
    
    def create_snapshot(self, target: str) -> Optional[TopologySnapshot]:
        """
        Create a snapshot of the current topology.
        
        Args:
            target: Target identifier
            
        Returns:
            TopologySnapshot if successful, None otherwise
        """
        with self._lock:
            if target not in self.targets:
                return None
            
            target_state = self.targets[target]
            
            snapshot = TopologySnapshot(
                timestamp=datetime.now(),
                endpoints=list(target_state.discovered_endpoints.values()),
                sessions=list(target_state.active_sessions.values()),
                state_transitions=list(target_state.state_transitions),
                current_state=target_state.current_state,
                metadata={
                    'target': target,
                    'base_url': target_state.base_url,
                    'global_parameters': target_state.global_parameters.copy(),
                    'auth_context': target_state.auth_context.copy(),
                }
            )
            
            # Add to history
            self.snapshots.append(snapshot)
            if len(self.snapshots) > self.max_snapshots:
                self.snapshots.pop(0)
            
            logger.debug(f"Created snapshot for target: {target}")
            return snapshot
    
    def get_snapshot_history(
        self,
        target: str,
        limit: Optional[int] = None
    ) -> List[TopologySnapshot]:
        """
        Get snapshot history for a target.
        
        Args:
            target: Target identifier
            limit: Optional limit on number of snapshots
            
        Returns:
            List of TopologySnapshot
        """
        with self._lock:
            target_snapshots = [
                s for s in self.snapshots
                if s.metadata.get('target') == target
            ]
            
            if limit:
                return target_snapshots[-limit:]
            return target_snapshots
    
    def get_target_summary(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Get a summary of a target's state.
        
        Args:
            target: Target identifier
            
        Returns:
            Summary dictionary or None if target not found
        """
        with self._lock:
            if target not in self.targets:
                return None
            
            target_state = self.targets[target]
            
            return {
                'target': target,
                'base_url': target_state.base_url,
                'current_state': target_state.current_state,
                'endpoint_count': len(target_state.discovered_endpoints),
                'session_count': len(target_state.active_sessions),
                'transition_count': len(target_state.state_transitions),
                'created_at': target_state.created_at,
                'last_updated': target_state.last_updated,
            }
    
    def cleanup_inactive_sessions(
        self,
        target: str,
        max_age_seconds: int = 3600
    ) -> int:
        """
        Remove inactive sessions older than max_age_seconds.
        
        Args:
            target: Target identifier
            max_age_seconds: Maximum age in seconds
            
        Returns:
            Number of sessions removed
        """
        with self._lock:
            if target not in self.targets:
                return 0
            
            now = datetime.now()
            to_remove = []
            
            for session_id, session in self.targets[target].active_sessions.items():
                age = (now - session.last_activity).total_seconds()
                if age > max_age_seconds:
                    to_remove.append(session_id)
            
            for session_id in to_remove:
                self.remove_session(target, session_id)
            
            logger.info(f"Cleaned up {len(to_remove)} inactive sessions")
            return len(to_remove)
    
    def clear_target(self, target: str) -> bool:
        """
        Clear all data for a target.
        
        Args:
            target: Target identifier
            
        Returns:
            True if cleared, False if target not found
        """
        with self._lock:
            if target not in self.targets:
                return False
            
            del self.targets[target]
            
            if self.current_target == target:
                self.current_target = None
            
            logger.info(f"Cleared target: {target}")
            return True
    
    def get_all_targets(self) -> List[str]:
        """
        Get all registered target identifiers.
        
        Returns:
            List of target identifiers
        """
        with self._lock:
            return list(self.targets.keys())