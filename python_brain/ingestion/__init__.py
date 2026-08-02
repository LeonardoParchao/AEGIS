"""
Ingestion module for AEGIS security scanner.

This module provides data ingestion capabilities for parsing OpenAPI/Swagger
specifications, ingesting PCAP network traffic files, and mapping the data
into an Abstract Syntax Tree (AST) for mathematical modelling by the Z3 solver.
"""

from .openapi_parser import (
    OpenAPIParser,
    OpenAPISpec,
    Endpoint,
    Parameter,
    Response,
    SecurityScheme,
    AuthType,
)

from .pcap_ingestor import (
    PcapIngestor,
    PcapAnalysis,
    IPPortPair,
    NetworkFlow,
    ProtocolSignature,
    Protocol,
)

from .topology_mapper import (
    TopologyMapper,
    TopologyAST,
    ASTNode,
    NodeType,
    State,
    Transition,
    Constraint,
    ConstraintType,
)

__all__ = [
    # OpenAPI Parser
    'OpenAPIParser',
    'OpenAPISpec',
    'Endpoint',
    'Parameter',
    'Response',
    'SecurityScheme',
    'AuthType',
    
    # PCAP Ingestor
    'PcapIngestor',
    'PcapAnalysis',
    'IPPortPair',
    'NetworkFlow',
    'ProtocolSignature',
    'Protocol',
    
    # Topology Mapper
    'TopologyMapper',
    'TopologyAST',
    'ASTNode',
    'NodeType',
    'State',
    'Transition',
    'Constraint',
    'ConstraintType',
]

__version__ = '0.1.0'
