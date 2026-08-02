"""
Topology mapper for AEGIS security scanner.

This module converts parsed OpenAPI and PCAP data into an Abstract Syntax Tree (AST).
It structures the data for mathematical modelling by the Z3 solver.
"""

from typing import Dict, List, Optional, Any, Union, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from .openapi_parser import OpenAPISpec
    from .pcap_ingestor import PcapAnalysis


class NodeType(Enum):
    """Types of AST nodes."""
    ROOT = "root"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    STATE = "state"
    TRANSITION = "transition"
    CONSTRAINT = "constraint"
    NETWORK_NODE = "network_node"
    NETWORK_EDGE = "network_edge"
    PROTOCOL = "protocol"
    AUTH_SCHEME = "auth_scheme"
    DATA_TYPE = "data_type"
    VARIABLE = "variable"
    OPERATION = "operation"


class ConstraintType(Enum):
    """Types of constraints for Z3 modelling."""
    EQUALITY = "equality"
    INEQUALITY = "inequality"
    LOGICAL_AND = "logical_and"
    LOGICAL_OR = "logical_or"
    IMPLICATION = "implication"
    EXISTS = "exists"
    FORALL = "forall"
    RANGE = "range"
    REGEX = "regex"
    CUSTOM = "custom"


@dataclass
class ASTNode:
    """Base class for AST nodes."""
    node_type: NodeType
    name: str
    children: List['ASTNode'] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    parent: Optional['ASTNode'] = None
    
    def add_child(self, child: 'ASTNode'):
        """Add a child node."""
        child.parent = self
        self.children.append(child)
    
    def find_children_by_type(self, node_type: NodeType) -> List['ASTNode']:
        """Find all children of a specific type."""
        result = []
        for child in self.children:
            if child.node_type == node_type:
                result.append(child)
            result.extend(child.find_children_by_type(node_type))
        return result


@dataclass
class Constraint:
    """Represents a constraint for Z3 solver."""
    constraint_type: ConstraintType
    variable: str
    value: Any
    operator: Optional[str] = None
    description: Optional[str] = None


@dataclass
class State:
    """Represents a state in the state machine."""
    name: str
    state_type: str  # e.g., 'authenticated', 'error', 'success'
    constraints: List[Constraint] = field(default_factory=list)
    transitions: List['Transition'] = field(default_factory=list)
    is_final: bool = False
    is_initial: bool = False


@dataclass
class Transition:
    """Represents a transition between states."""
    from_state: str
    to_state: str
    trigger: str  # e.g., HTTP method, event
    conditions: List[Constraint] = field(default_factory=list)
    action: Optional[str] = None


@dataclass
class TopologyAST:
    """Abstract Syntax Tree representing the system topology."""
    root: ASTNode
    states: Dict[str, State] = field(default_factory=dict)
    variables: Dict[str, Any] = field(default_factory=dict)
    constraints: List[Constraint] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TopologyMapper:
    """
    Convert parsed OpenAPI and PCAP data into an AST.
    
    Structure the data for mathematical modelling by the Z3 solver.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the topology mapper.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.state_counter = 0
        
    def map_openapi_to_ast(self, openapi_spec: 'OpenAPISpec') -> TopologyAST:
        """
        Convert OpenAPI specification to AST.
        
        Args:
            openapi_spec: OpenAPISpec object from openapi_parser
            
        Returns:
            TopologyAST representing the API structure
        """
        
        # Create root node
        root = ASTNode(
            node_type=NodeType.ROOT,
            name="api_topology",
            attributes={
                'title': openapi_spec.title,
                'version': openapi_spec.version,
                'base_url': openapi_spec.base_url
            }
        )
        
        # Create service node
        service_node = ASTNode(
            node_type=NodeType.SERVICE,
            name=openapi_spec.title,
            attributes={
                'description': openapi_spec.description,
                'base_url': openapi_spec.base_url
            }
        )
        root.add_child(service_node)
        
        # Add authentication schemes
        for scheme_name, scheme in openapi_spec.security_schemes.items():
            auth_node = ASTNode(
                node_type=NodeType.AUTH_SCHEME,
                name=scheme_name,
                attributes={
                    'type': scheme.type.value,
                    'scheme': scheme.scheme,
                    'bearer_format': scheme.bearer_format,
                    'location': scheme.location
                }
            )
            service_node.add_child(auth_node)
        
        # Create state machine
        states = self._create_state_machine_from_openapi(openapi_spec)
        
        # Add endpoints
        for endpoint in openapi_spec.endpoints:
            endpoint_node = self._create_endpoint_node(endpoint, states)
            service_node.add_child(endpoint_node)
        
        ast = TopologyAST(root=root, states=states)
        ast.metadata['source'] = 'openapi'
        
        return ast
    
    def map_pcap_to_ast(self, pcap_analysis: 'PcapAnalysis') -> TopologyAST:
        """
        Convert PCAP analysis to AST.
        
        Args:
            pcap_analysis: PcapAnalysis object from pcap_ingestor
            
        Returns:
            TopologyAST representing the network topology
        """
        
        # Create root node
        root = ASTNode(
            node_type=NodeType.ROOT,
            name="network_topology",
            attributes={
                'total_packets': pcap_analysis.total_packets,
                'file_path': pcap_analysis.file_path
            }
        )
        
        # Create network nodes
        network_nodes = {}
        for pair in pcap_analysis.unique_ip_port_pairs:
            node_key = f"{pair.ip_address}:{pair.port}"
            if node_key not in network_nodes:
                node = ASTNode(
                    node_type=NodeType.NETWORK_NODE,
                    name=node_key,
                    attributes={
                        'ip_address': pair.ip_address,
                        'port': pair.port,
                        'protocol': pair.protocol.value,
                        'is_server': pair.is_server,
                        'service': pair.service
                    }
                )
                network_nodes[node_key] = node
                root.add_child(node)
        
        # Create network edges (flows)
        for flow in pcap_analysis.network_flows:
            edge = ASTNode(
                node_type=NodeType.NETWORK_EDGE,
                name=f"{flow.src_ip}:{flow.src_port}-{flow.dst_ip}:{flow.dst_port}",
                attributes={
                    'src_ip': flow.src_ip,
                    'src_port': flow.src_port,
                    'dst_ip': flow.dst_ip,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol.value,
                    'packet_count': flow.packet_count,
                    'byte_count': flow.byte_count,
                    'duration': flow.duration
                }
            )
            root.add_child(edge)
        
        # Add proprietary protocols
        for protocol in pcap_analysis.proprietary_protocols:
            protocol_node = ASTNode(
                node_type=NodeType.PROTOCOL,
                name=protocol.name,
                attributes={
                    'pattern': protocol.pattern.hex(),
                    'offset': protocol.offset,
                    'confidence': protocol.confidence,
                    'description': protocol.description
                }
            )
            root.add_child(protocol_node)
        
        # Create state machine from network flows
        states = self._create_state_machine_from_pcap(pcap_analysis)
        
        ast = TopologyAST(root=root, states=states)
        ast.metadata['source'] = 'pcap'
        
        return ast
    
    def merge_asts(self, *asts: TopologyAST) -> TopologyAST:
        """
        Merge multiple ASTs into a single topology.
        
        Args:
            *asts: Variable number of TopologyAST objects to merge
            
        Returns:
            Merged TopologyAST
        """
        if not asts:
            raise ValueError("At least one AST must be provided for merging")
        
        if len(asts) == 1:
            return asts[0]
        
        # Create new root
        merged_root = ASTNode(
            node_type=NodeType.ROOT,
            name="merged_topology",
            attributes={
                'sources': [ast.metadata.get('source', 'unknown') for ast in asts]
            }
        )
        
        # Merge all children
        merged_states = {}
        for ast in asts:
            for child in ast.root.children:
                # Create a copy of the child
                new_child = ASTNode(
                    node_type=child.node_type,
                    name=child.name,
                    attributes=child.attributes.copy()
                )
                merged_root.add_child(new_child)
            
            # Merge states
            for state_name, state in ast.states.items():
                if state_name not in merged_states:
                    merged_states[state_name] = state
                else:
                    # Merge constraints and transitions
                    merged_states[state_name].constraints.extend(state.constraints)
                    merged_states[state_name].transitions.extend(state.transitions)
        
        return TopologyAST(root=merged_root, states=merged_states)
    
    def _create_endpoint_node(self, endpoint, states: Dict[str, State]) -> ASTNode:
        """Create an AST node for an endpoint."""
        node = ASTNode(
            node_type=NodeType.ENDPOINT,
            name=f"{endpoint.method}_{endpoint.path}",
            attributes={
                'path': endpoint.path,
                'method': endpoint.method,
                'operation_id': endpoint.operation_id,
                'summary': endpoint.summary
            }
        )
        
        # Add parameters
        for param in endpoint.parameters:
            param_node = ASTNode(
                node_type=NodeType.PARAMETER,
                name=param.name,
                attributes={
                    'in': param.param_in,
                    'required': param.required,
                    'type': param.param_type,
                    'schema': param.schema,
                    'default': param.default
                }
            )
            node.add_child(param_node)
        
        # Add state reference
        state_name = f"{endpoint.method}_{endpoint.path}_state"
        if state_name in states:
            node.attributes['state'] = state_name
        
        return node
    
    def _create_state_machine_from_openapi(self, openapi_spec) -> Dict[str, State]:
        """Create a state machine from OpenAPI specification."""
        states = {}
        
        # Create initial state
        initial_state = State(
            name="initial",
            state_type="initial",
            is_initial=True
        )
        states["initial"] = initial_state
        
        # Create states for each endpoint
        for endpoint in openapi_spec.endpoints:
            state_name = f"{endpoint.method}_{endpoint.path}_state"
            
            # Create constraints from parameters
            constraints = []
            for param in endpoint.parameters:
                if param.required:
                    constraints.append(Constraint(
                        constraint_type=ConstraintType.EXISTS,
                        variable=param.name,
                        value=True,
                        description=f"Required parameter: {param.name}"
                    ))
                
                if param.param_type:
                    constraints.append(Constraint(
                        constraint_type=ConstraintType.CUSTOM,
                        variable=param.name,
                        value=param.param_type,
                        operator="type",
                        description=f"Parameter type: {param.param_type}"
                    ))
            
            # Create state
            state = State(
                name=state_name,
                state_type="endpoint",
                constraints=constraints
            )
            states[state_name] = state
            
            # Create transition from initial state
            transition = Transition(
                from_state="initial",
                to_state=state_name,
                trigger=endpoint.method,
                conditions=constraints
            )
            initial_state.transitions.append(transition)
        
        return states
    
    def _create_state_machine_from_pcap(self, pcap_analysis) -> Dict[str, State]:
        """Create a state machine from PCAP analysis."""
        states = {}
        
        # Create initial state
        initial_state = State(
            name="network_initial",
            state_type="initial",
            is_initial=True
        )
        states["network_initial"] = initial_state
        
        # Create states for each unique IP/port pair
        for pair in pcap_analysis.unique_ip_port_pairs:
            state_name = f"node_{pair.ip_address}_{pair.port}"
            
            constraints = []
            if pair.is_server:
                constraints.append(Constraint(
                    constraint_type=ConstraintType.CUSTOM,
                    variable="service",
                    value=pair.service or "unknown",
                    operator="is_server",
                    description=f"Server port: {pair.port}"
                ))
            
            state = State(
                name=state_name,
                state_type="network_node",
                constraints=constraints
            )
            states[state_name] = state
        
        # Create transitions from network flows
        for flow in pcap_analysis.network_flows:
            src_state = f"node_{flow.src_ip}_{flow.src_port}"
            dst_state = f"node_{flow.dst_ip}_{flow.dst_port}"
            
            if src_state in states and dst_state in states:
                transition = Transition(
                    from_state=src_state,
                    to_state=dst_state,
                    trigger=flow.protocol.value,
                    conditions=[],
                    action="network_communication"
                )
                states[src_state].transitions.append(transition)
        
        return states
    
    def generate_z3_constraints(self, ast: TopologyAST) -> List[str]:
        """
        Generate Z3 constraint strings from the AST.
        
        Args:
            ast: TopologyAST object
            
        Returns:
            List of Z3 constraint strings
        """
        constraints = []
        
        # Generate constraints from states
        for state_name, state in ast.states.items():
            for constraint in state.constraints:
                z3_str = self._constraint_to_z3(constraint)
                if z3_str:
                    constraints.append(z3_str)
        
        # Generate constraints from transitions
        for state_name, state in ast.states.items():
            for transition in state.transitions:
                for condition in transition.conditions:
                    z3_str = self._constraint_to_z3(condition)
                    if z3_str:
                        constraints.append(z3_str)
        
        return constraints
    
    def _constraint_to_z3(self, constraint: Constraint) -> Optional[str]:
        """Convert a constraint to Z3 syntax."""
        if constraint.constraint_type == ConstraintType.EQUALITY:
            return f"(= {constraint.variable} {constraint.value})"
        elif constraint.constraint_type == ConstraintType.INEQUALITY:
            return f"(not (= {constraint.variable} {constraint.value}))"
        elif constraint.constraint_type == ConstraintType.EXISTS:
            return f"(exists (({constraint.variable} Bool)) {constraint.variable})"
        elif constraint.constraint_type == ConstraintType.IMPLICATION:
            return f"(=> {constraint.variable} {constraint.value})"
        elif constraint.constraint_type == ConstraintType.CUSTOM:
            if constraint.operator == "type":
                return f"; Type constraint: {constraint.variable} is {constraint.value}"
            return f"; Custom constraint: {constraint.description}"
        return None
