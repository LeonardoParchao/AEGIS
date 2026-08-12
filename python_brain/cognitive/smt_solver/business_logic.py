"""
Epistemic logic policies for AEGIS security scanner.

This module models application intent using epistemic logic and defines
security policies that prevent unauthorized state transitions.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security levels for state transitions."""
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    AUTHORIZED = "authorized"
    ADMIN = "admin"
    CRITICAL = "critical"


@dataclass
class SecurityPolicy:
    """Represents a security policy constraint."""
    policy_id: str
    source_states: Set[str]
    target_state: str
    required_conditions: Dict[str, Any]
    security_level: SecurityLevel
    description: str


@dataclass
class EpistemicModel:
    """Epistemic model of application state and knowledge."""
    states: Set[str] = field(default_factory=set)
    transitions: Dict[str, Set[str]] = field(default_factory=dict)
    knowledge_base: Dict[str, Any] = field(default_factory=dict)
    security_policies: List[SecurityPolicy] = field(default_factory=list)


class BusinessLogicAnalyzer:
    """
    Analyze business logic constraints using epistemic logic.
    
    Models application intent to prevent unauthorized state transitions
    and calculates potential bypass paths using Z3.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the business logic analyzer.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.epistemic_model = EpistemicModel()
        self._initialize_default_policies()
        
    def _initialize_default_policies(self):
        """Initialize default security policies for common patterns."""
        default_policies = [
            SecurityPolicy(
                policy_id="auth_required",
                source_states={"unauthenticated", "guest"},
                target_state="authenticated",
                required_conditions={
                    "valid_credentials": True,
                    "session_token": "present"
                },
                security_level=SecurityLevel.AUTHENTICATED,
                description="Authentication required for authenticated state"
            ),
            SecurityPolicy(
                policy_id="admin_required",
                source_states={"authenticated", "authorized"},
                target_state="admin",
                required_conditions={
                    "role": "admin",
                    "elevated_privileges": True
                },
                security_level=SecurityLevel.ADMIN,
                description="Admin role required for admin state"
            ),
            SecurityPolicy(
                policy_id="payment_required",
                source_states={"cart", "checkout"},
                target_state="order_complete",
                required_conditions={
                    "payment_processed": True,
                    "payment_verified": True,
                    "inventory_available": True
                },
                security_level=SecurityLevel.AUTHORIZED,
                description="Payment verification required for order completion"
            ),
            SecurityPolicy(
                policy_id="data_access_control",
                source_states={"*"},
                target_state="sensitive_data_access",
                required_conditions={
                    "authorization": True,
                    "data_classification": "authorized_level"
                },
                security_level=SecurityLevel.CRITICAL,
                description="Authorization required for sensitive data access"
            )
        ]
        
        self.epistemic_model.security_policies.extend(default_policies)
        logger.info(f"Initialized {len(default_policies)} default security policies")
    
    def add_state(self, state_name: str):
        """
        Add a state to the epistemic model.
        
        Args:
            state_name: Name of the state to add
        """
        self.epistemic_model.states.add(state_name)
        if state_name not in self.epistemic_model.transitions:
            self.epistemic_model.transitions[state_name] = set()
    
    def add_transition(self, source_state: str, target_state: str):
        """
        Add a state transition to the model.
        
        Args:
            source_state: Source state
            target_state: Target state
        """
        self.add_state(source_state)
        self.add_state(target_state)
        self.epistemic_model.transitions[source_state].add(target_state)
    
    def add_security_policy(self, policy: SecurityPolicy):
        """
        Add a custom security policy.
        
        Args:
            policy: SecurityPolicy to add
        """
        self.epistemic_model.security_policies.append(policy)
        logger.info(f"Added security policy: {policy.policy_id}")
    
    def get_policy_for_transition(self, source_state: str, target_state: str) -> Optional[SecurityPolicy]:
        """
        Get the security policy for a specific transition.
        
        Args:
            source_state: Source state
            target_state: Target state
            
        Returns:
            SecurityPolicy if found, None otherwise
        """
        for policy in self.epistemic_model.security_policies:
            if (target_state == policy.target_state and 
                (source_state in policy.source_states or "*" in policy.source_states)):
                return policy
        return None
    
    def validate_transition(
        self,
        source_state: str,
        target_state: str,
        current_conditions: Dict[str, Any]
    ) -> tuple[bool, List[str]]:
        """
        Validate if a state transition is allowed under current conditions.
        
        Args:
            source_state: Current state
            target_state: Target state
            current_conditions: Current system conditions
            
        Returns:
            Tuple of (is_valid, list of policy violations)
        """
        policy = self.get_policy_for_transition(source_state, target_state)
        
        if not policy:
            # No specific policy, allow transition
            return True, []
        
        violations = []
        
        # Check required conditions
        for condition_key, required_value in policy.required_conditions.items():
            current_value = current_conditions.get(condition_key)
            
            if required_value is True and not current_value:
                violations.append(f"Missing required condition: {condition_key}")
            elif required_value is False and current_value:
                violations.append(f"Condition should be false: {condition_key}")
            elif isinstance(required_value, str) and current_value != required_value:
                violations.append(f"Condition mismatch: {condition_key} (expected: {required_value}, got: {current_value})")
            elif isinstance(required_value, (list, set)) and current_value not in required_value:
                violations.append(f"Condition value not allowed: {condition_key}")
        
        is_valid = len(violations) == 0
        return is_valid, violations
    
    def calculate_bypass_paths(
        self,
        target_state: str,
        current_state: str,
        current_conditions: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Calculate potential bypass paths to reach a target state.
        
        Args:
            target_state: Target state to reach
            current_state: Current state
            current_conditions: Current system conditions
            
        Returns:
            List of potential bypass paths with constraints
        """
        bypass_paths = []
        
        # Find all paths to target state using BFS
        visited = set()
        queue = [(current_state, [], current_conditions)]
        
        while queue:
            state, path, conditions = queue.pop(0)
            
            if state == target_state:
                bypass_paths.append({
                    'path': path,
                    'final_conditions': conditions,
                    'confidence': self._calculate_path_confidence(path, conditions)
                })
                continue
            
            if state in visited:
                continue
            
            visited.add(state)
            
            # Explore transitions
            for next_state in self.epistemic_model.transitions.get(state, set()):
                policy = self.get_policy_for_transition(state, next_state)
                
                if policy:
                    # Calculate conditions needed for this transition
                    new_conditions = conditions.copy()
                    new_conditions.update(policy.required_conditions)
                    
                    new_path = path + [(state, next_state, policy.policy_id)]
                    queue.append((next_state, new_path, new_conditions))
        
        logger.info(f"Calculated {len(bypass_paths)} potential bypass paths to {target_state}")
        return bypass_paths
    
    def _calculate_path_confidence(self, path: List[tuple], conditions: Dict[str, Any]) -> float:
        """
        Calculate confidence score for a bypass path.
        
        Args:
            path: List of (source, target, policy_id) tuples
            conditions: Final conditions
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not path:
            return 0.0
        
        # More complex paths have lower confidence
        length_penalty = 1.0 / (1.0 + len(path) * 0.1)
        
        # Paths with more required conditions have lower confidence
        condition_penalty = 1.0 / (1.0 + len(conditions) * 0.05)
        
        return min(1.0, length_penalty * condition_penalty)
    
    def get_model_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the epistemic model.
        
        Returns:
            Dictionary containing model statistics and structure
        """
        return {
            'total_states': len(self.epistemic_model.states),
            'total_transitions': sum(len(transitions) for transitions in self.epistemic_model.transitions.values()),
            'total_policies': len(self.epistemic_model.security_policies),
            'states': list(self.epistemic_model.states),
            'security_levels': {
                policy.security_level.value: len([p for p in self.epistemic_model.security_policies if p.security_level == policy.security_level])
                for policy in set(self.epistemic_model.security_policies)
            }
        }
