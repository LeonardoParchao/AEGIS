"""
Cognitive module for AEGIS security scanner.

This module provides SMT-guided fuzzing and constraint solving capabilities
for security testing, including payload generation, network protocol fuzzing,
and Z3-based state machine analysis.
"""

from .fuzzer import (
    PayloadGenerator,
    PayloadType,
    ScapyFuzzer,
    ProtocolLayer,
)

__all__ = [
    'PayloadGenerator',
    'PayloadType',
    'ScapyFuzzer',
    'ProtocolLayer',
]

__version__ = '0.1.0'
