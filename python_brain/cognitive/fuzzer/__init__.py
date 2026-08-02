"""
Fuzzer module for AEGIS security scanner.

This module provides SMT-guided fuzzing capabilities, generating payloads
based on logical bypass paths calculated by the Z3 solver, and network
protocol fuzzing using Scapy.
"""

from .payload_generator import PayloadGenerator, PayloadType
from .scapy_fuzzer import ScapyFuzzer, ProtocolLayer

__all__ = [
    'PayloadGenerator',
    'PayloadType',
    'ScapyFuzzer',
    'ProtocolLayer',
]

__version__ = '0.1.0'
