"""
Verification module for AEGIS security scanner.

This module provides verification capabilities for confirming vulnerabilities through
eBPF kernel monitoring, mathematical proof validation, and sandboxed dynamic testing.
It interfaces with the Rust userspace/eBPF layers via PyO3 to achieve zero false-positive
vulnerability confirmation.
"""

from .ebpf_verifier import (
    EBPFVerifier,
    KernelTracepoint,
    TraceEvent,
    VerificationResult,
    BPFProgramType,
)

from .proof_validator import (
    ProofValidator,
    KernelSink,
    TraceAnalysis,
    ValidationResult,
    SinkType,
)

from .sandbox_runner import (
    SandboxRunner,
    SandboxConfig,
    ContainerEnvironment,
    IsolationLevel,
    ExecutionResult,
)

__all__ = [
    # eBPF Verifier
    'EBPFVerifier',
    'KernelTracepoint',
    'TraceEvent',
    'VerificationResult',
    'BPFProgramType',
    
    # Proof Validator
    'ProofValidator',
    'KernelSink',
    'TraceAnalysis',
    'ValidationResult',
    'SinkType',
    
    # Sandbox Runner
    'SandboxRunner',
    'SandboxConfig',
    'ContainerEnvironment',
    'IsolationLevel',
    'ExecutionResult',
]

__version__ = '0.1.0'
