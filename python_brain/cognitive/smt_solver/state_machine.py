"""
State machine analysis for AEGIS security scanner.

This module translates application topology into Z3 set theory and state constraints,
defining logical rules for state transitions and security properties.
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class StateType(Enum):
    """Types of states in the application."""
    INITIAL = "initial"
    INTERMEDIATE = "intermediate"
    TERMINAL = "terminal"
    ERROR = "error"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SENSITIVE = "sensitive"


@dataclass
class State:
    """Represents a state in the application."""
    name: str
    state_type: StateType
    metadata: Dict[str, Any] = field(default_factory=dict)
    entry_conditions: Dict[str, Any] = field(default_factory=dict)
    exit_conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Transition:
    """Represents a transition between states."""
    source_state: str
    target_state: str
    trigger: str
    guard_conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateConstraint:
    """Represents a Z3 constraint for state validation."""
    constraint_id: str
    expression: str
    variables: Set[str]
    description: str


class StateMachineAnalyzer:
    """
    Analyze application state machines and generate Z3 constraints.
    
    Translates topology AST into Z3 set theory and state constraints,
    defining logical rules for secure state transitions.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the state machine analyzer.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.states: Dict[str, State] = {}
        self.transitions: List[Transition] = []
        self.constraints: List[StateConstraint] = []
        self._initialize_default_states()
        
    def _initialize_default_states(self):
        """Initialize default states for common application patterns."""
        default_states = [
            State("initial", StateType.INITIAL, {"description": "Application entry point"}),
            State("unauthenticated", StateType.AUTHENTICATION, {"description": "User not authenticated"}),
            State("authenticated", StateType.AUTHENTICATION, {"description": "User authenticated"}),
            State("authorized", StateType.AUTHORIZATION, {"description": "User authorized"}),
            State("admin", StateType.SENSITIVE, {"description": "Administrator access"}),
            State("error", StateType.ERROR, {"description": "Error state"}),
            State("terminal", StateType.TERMINAL, {"description": "Terminal state"}),
        ]
        
        for state in default_states:
            self.states[state.name] = state
        
        logger.info(f"Initialized {len(default_states)} default states")
    
    def add_state(self, state: State):
        """
        Add a state to the state machine.
        
        Args:
            state: State object to add
        """
        self.states[state.name] = state
        logger.debug(f"Added state: {state.name}")
    
    def add_transition(self, transition: Transition):
        """
        Add a transition to the state machine.
        
        Args:
            transition: Transition object to add
        """
        self.transitions.append(transition)
        logger.debug(f"Added transition: {transition.source_state} -> {transition.target_state}")
    
    def get_state(self, state_name: str) -> Optional[State]:
        """
        Get a state by name.
        
        Args:
            state_name: Name of the state
            
        Returns:
            State object if found, None otherwise
        """
        return self.states.get(state_name)
    
    def get_transitions_from_state(self, state_name: str) -> List[Transition]:
        """
        Get all transitions from a specific state.
        
        Args:
            state_name: Source state name
            
        Returns:
            List of transitions from the state
        """
        return [t for t in self.transitions if t.source_state == state_name]
    
    def get_transitions_to_state(self, state_name: str) -> List[Transition]:
        """
        Get all transitions to a specific state.
        
        Args:
            state_name: Target state name
            
        Returns:
            List of transitions to the state
        """
        return [t for t in self.transitions if t.target_state == state_name]
    
    def generate_z3_constraints(self) -> List[StateConstraint]:
        """
        Generate Z3 constraints from the state machine.
        
        Returns:
            List of StateConstraint objects with Z3 expressions
        """
        self.constraints = []
        
        # Generate state existence constraints
        for state_name, state in self.states.items():
            constraint = StateConstraint(
                constraint_id=f"state_exists_{state_name}",
                expression=f"Exists(Var('{state_name}'))",
                variables={state_name},
                description=f"State {state_name} must exist"
            )
            self.constraints.append(constraint)
        
        # Generate transition constraints
        for transition in self.transitions:
            variables = {transition.source_state, transition.target_state}
            
            # Basic transition constraint
            constraint = StateConstraint(
                constraint_id=f"transition_{transition.source_state}_to_{transition.target_state}",
                expression=f"Implies(Var('{transition.source_state}'), Var('{transition.target_state}'))",
                variables=variables,
                description=f"Transition from {transition.source_state} to {transition.target_state}"
            )
            self.constraints.append(constraint)
            
            # Guard condition constraints
            for guard_key, guard_value in transition.guard_conditions.items():
                guard_constraint = StateConstraint(
                    constraint_id=f"guard_{transition.source_state}_to_{transition.target_state}_{guard_key}",
                    expression=f"Implies(And(Var('{transition.source_state}'), Var('{guard_key}') == {self._format_z3_value(guard_value)}), Var('{transition.target_state}'))",
                    variables={transition.source_state, transition.target_state, guard_key},
                    description=f"Guard condition {guard_key} for transition"
                )
                self.constraints.append(guard_constraint)
        
        # Generate security-specific constraints
        self._generate_security_constraints()
        
        logger.info(f"Generated {len(self.constraints)} Z3 constraints")
        return self.constraints
    
    def _generate_security_constraints(self):
        """Generate security-specific constraints."""
        # Admin access constraint
        admin_constraint = StateConstraint(
            constraint_id="admin_access_control",
            expression="Implies(Var('admin'), And(Var('authenticated'), Var('role') == 'admin'))",
            variables={"admin", "authenticated", "role"},
            description="Admin state requires authentication and admin role"
        )
        self.constraints.append(admin_constraint)
        
        # Sensitive data access constraint
        sensitive_constraint = StateConstraint(
            constraint_id="sensitive_data_access",
            expression="Implies(Var('sensitive_data_access'), And(Var('authorized'), Var('clearance_level') >= Var('data_classification')))",
            variables={"sensitive_data_access", "authorized", "clearance_level", "data_classification"},
            description="Sensitive data access requires proper authorization and clearance"
        )
        self.constraints.append(sensitive_constraint)
        
        # Payment constraint
        payment_constraint = StateConstraint(
            constraint_id="payment_verification",
            expression="Implies(Var('order_complete'), And(Var('payment_processed'), Var('payment_verified')))",
            variables={"order_complete", "payment_processed", "payment_verified"},
            description="Order completion requires verified payment"
        )
        self.constraints.append(payment_constraint)
    
    def _format_z3_value(self, value: Any) -> str:
        """
        Format a value for Z3 expression.
        
        Args:
            value: Value to format
            
        Returns:
            Formatted string for Z3
        """
        if isinstance(value, bool):
            return "True" if value else "False"
        elif isinstance(value, str):
            return f'"{value}"'
        elif isinstance(value, (int, float)):
            return str(value)
        else:
            return str(value)
    
    def find_reachable_states(self, start_state: str) -> Set[str]:
        """
        Find all states reachable from a given start state.
        
        Args:
            start_state: Starting state name
            
        Returns:
            Set of reachable state names
        """
        reachable = set()
        queue = [start_state]
        
        while queue:
            current = queue.pop(0)
            if current in reachable:
                continue
            
            reachable.add(current)
            
            for transition in self.get_transitions_from_state(current):
                if transition.target_state not in reachable:
                    queue.append(transition.target_state)
        
        return reachable
    
    def find_paths_to_state(self, target_state: str, start_state: str = "initial") -> List[List[str]]:
        """
        Find all paths from start state to target state.
        
        Args:
            target_state: Target state name
            start_state: Starting state name
            
        Returns:
            List of paths (each path is a list of state names)
        """
        paths = []
        self._find_paths_recursive(start_state, target_state, [], paths)
        return paths
    
    def _find_paths_recursive(self, current: str, target: str, current_path: List[str], all_paths: List[List[str]]):
        """
        Recursively find paths from current to target state.
        
        Args:
            current: Current state
            target: Target state
            current_path: Current path being explored
            all_paths: List to store all found paths
        """
        if current == target:
            all_paths.append(current_path + [current])
            return
        
        if current in current_path:  # Prevent cycles
            return
        
        new_path = current_path + [current]
        
        for transition in self.get_transitions_from_state(current):
            self._find_paths_recursive(transition.target_state, target, new_path, all_paths)
    
    def validate_state_machine(self) -> tuple[bool, List[str]]:
        """
        Validate the state machine for consistency and security issues.
        
        Returns:
            Tuple of (is_valid, list of validation errors)
        """
        errors = []
        
        # Check for unreachable states
        reachable_from_initial = self.find_reachable_states("initial")
        for state_name in self.states:
            if state_name not in reachable_from_initial and state_name != "initial":
                errors.append(f"State {state_name} is unreachable from initial state")
        
        # Check for states with no outgoing transitions (except terminal)
        for state_name, state in self.states.items():
            if state.state_type != StateType.TERMINAL:
                outgoing = self.get_transitions_from_state(state_name)
                if not outgoing:
                    errors.append(f"State {state_name} has no outgoing transitions but is not terminal")
        
        # Check for terminal states with outgoing transitions
        for state_name, state in self.states.items():
            if state.state_type == StateType.TERMINAL:
                outgoing = self.get_transitions_from_state(state_name)
                if outgoing:
                    errors.append(f"Terminal state {state_name} has outgoing transitions")
        
        # Check for orphaned states (no incoming transitions except initial)
        for state_name in self.states:
            if state_name != "initial":
                incoming = self.get_transitions_to_state(state_name)
                if not incoming:
                    errors.append(f"State {state_name} has no incoming transitions")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def get_state_machine_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the state machine.
        
        Returns:
            Dictionary containing state machine statistics
        """
        state_types = {}
        for state in self.states.values():
            state_types[state.state_type.value] = state_types.get(state.state_type.value, 0) + 1
        
        return {
            'total_states': len(self.states),
            'total_transitions': len(self.transitions),
            'total_constraints': len(self.constraints),
            'state_types': state_types,
            'states': list(self.states.keys()),
            'validation_result': self.validate_state_machine()
        }
