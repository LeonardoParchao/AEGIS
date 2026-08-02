"""
Orchestrator module for AEGIS security scanner.

This module provides coordination between the Z3 cognitive engine and the Rust I/O engines.
It manages the lifecycle of scanning modules, handles threading and async event loops,
and maintains the global state of the target topology.
"""

from .scanner_manager import (
    ScannerManager,
    ScanPhase,
    ScanConfig,
    ScanResult,
    ScannerStatus,
)

from .target_state import (
    TargetStateManager,
    TargetState,
    SessionInfo,
    DiscoveredEndpoint,
    StateTransition,
    TopologySnapshot,
)

__all__ = [
    # Scanner Manager
    'ScannerManager',
    'ScanPhase',
    'ScanConfig',
    'ScanResult',
    'ScannerStatus',
    
    # Target State Manager
    'TargetStateManager',
    'TargetState',
    'SessionInfo',
    'DiscoveredEndpoint',
    'StateTransition',
    'TopologySnapshot',
]

__version__ = '0.1.0'
