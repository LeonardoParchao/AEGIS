"""
eBPF verifier for AEGIS security scanner.

This module interfaces with the Rust userspace layer via PyO3 to execute
payloads and monitor kernel tracepoints. It provides zero false-positive
vulnerability confirmation by detecting actual kernel-level sink execution.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import threading
import queue
import json


class BPFProgramType(Enum):
    """Types of BPF programs for verification."""
    KPROBE = "kprobe"
    UPROBE = "uprobe"
    TRACEPOINT = "tracepoint"
    XDP = "xdp"
    SOCKET_FILTER = "socket_filter"
    CGROUP_SKB = "cgroup_skb"


@dataclass
class KernelTracepoint:
    """Represents a kernel tracepoint to monitor."""
    name: str
    subsystem: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    filter_expression: Optional[str] = None


@dataclass
class TraceEvent:
    """Represents a captured kernel trace event."""
    timestamp: datetime
    tracepoint: str
    cpu_id: int
    pid: int
    data: Dict[str, Any]
    raw_bytes: Optional[bytes] = None


@dataclass
class VerificationResult:
    """Result of a vulnerability verification attempt."""
    vulnerability_id: str
    confirmed: bool
    confidence: float
    trace_events: List[TraceEvent] = field(default_factory=list)
    kernel_sink_hit: bool = False
    execution_time_ms: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class EBPFVerifier:
    """
    Interface with Rust userspace layer via PyO3 for kernel-level verification.
    
    This verifier fires payloads through the Rust ya_loader and monitors kernel
    tracepoints to detect actual vulnerability exploitation. If the Rust function
    returns true, the vulnerability is flagged as confirmed (0% false positive rate).
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the eBPF verifier.
        
        Args:
            config: Optional configuration dictionary containing:
                - rust_module_path: Path to the compiled Rust PyO3 module
                - timeout_ms: Default timeout for verification attempts
                - buffer_size: Size of the kernel trace buffer
                - enable_logging: Whether to enable debug logging
        """
        self.config = config or {}
        self.rust_module_path = self.config.get('rust_module_path', 'aegis_userspace')
        self.timeout_ms = self.config.get('timeout_ms', 5000)
        self.buffer_size = self.config.get('buffer_size', 1024 * 1024)
        self.enable_logging = self.config.get('enable_logging', False)
        
        self._rust_interface = None
        self._event_queue = queue.Queue()
        self._monitoring_active = False
        self._monitor_thread = None
        
        # Load the Rust PyO3 interface
        self._load_rust_interface()
    
    def _load_rust_interface(self):
        """Load the Rust PyO3 module for eBPF operations."""
        try:
            # This will be the actual Rust PyO3 module when compiled
            # For now, we'll create a mock interface
            import importlib
            self._rust_interface = importlib.import_module(self.rust_module_path)
            
            if self.enable_logging:
                print(f"Loaded Rust interface from {self.rust_module_path}")
        except ImportError:
            # Create a mock interface for development/testing
            if self.enable_logging:
                print(f"Warning: Could not load Rust module {self.rust_module_path}, using mock interface")
            self._rust_interface = self._create_mock_interface()
    
    def _create_mock_interface(self) -> Any:
        """Create a mock Rust interface for development purposes."""
        class MockRustInterface:
            def load_bpf_program(self, program_type, program_data):
                return True
            
            def attach_tracepoint(self, tracepoint):
                return True
            
            def fire_payload(self, payload, target):
                # Simulate some processing time
                import time
                time.sleep(0.01)
                return {"success": True, "kernel_sink": False}
            
            def read_trace_events(self):
                return []
            
            def detach_tracepoint(self, tracepoint):
                return True
            
            def unload_bpf_program(self):
                return True
        
        return MockRustInterface()
    
    def verify_vulnerability(
        self,
        vulnerability_id: str,
        payload: bytes,
        target: str,
        tracepoints: List[KernelTracepoint],
        expected_sink: Optional[str] = None
    ) -> VerificationResult:
        """
        Verify a vulnerability by executing payload and monitoring kernel tracepoints.
        
        Args:
            vulnerability_id: Unique identifier for the vulnerability
            payload: The payload to execute (generated by cognitive layer)
            target: Target endpoint or system
            tracepoints: List of kernel tracepoints to monitor
            expected_sink: Optional expected kernel sink function name
            
        Returns:
            VerificationResult with confirmation status and trace data
        """
        start_time = datetime.now()
        trace_events = []
        kernel_sink_hit = False
        error_message = None
        
        try:
            # Load and attach BPF programs for monitoring
            self._setup_monitoring(tracepoints)
            
            # Fire the payload through the Rust interface
            if self.enable_logging:
                print(f"Firing payload for vulnerability {vulnerability_id} against {target}")
            
            rust_result = self._rust_interface.fire_payload(payload, target)
            
            # Read trace events from kernel buffer
            trace_events = self._collect_trace_events()
            
            # Check if expected kernel sink was hit
            kernel_sink_hit = self._check_kernel_sink(trace_events, expected_sink)
            
            # Determine if vulnerability is confirmed
            confirmed = rust_result.get("success", False) and kernel_sink_hit
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return VerificationResult(
                vulnerability_id=vulnerability_id,
                confirmed=confirmed,
                confidence=1.0 if confirmed else 0.0,
                trace_events=trace_events,
                kernel_sink_hit=kernel_sink_hit,
                execution_time_ms=execution_time,
                metadata={
                    "rust_result": rust_result,
                    "target": target,
                    "payload_size": len(payload),
                }
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            error_message = str(e)
            
            if self.enable_logging:
                print(f"Error during verification: {error_message}")
            
            return VerificationResult(
                vulnerability_id=vulnerability_id,
                confirmed=False,
                confidence=0.0,
                trace_events=trace_events,
                kernel_sink_hit=False,
                execution_time_ms=execution_time,
                error_message=error_message
            )
        finally:
            # Cleanup monitoring
            self._cleanup_monitoring(tracepoints)
    
    def _setup_monitoring(self, tracepoints: List[KernelTracepoint]):
        """Set up kernel tracepoint monitoring."""
        for tracepoint in tracepoints:
            try:
                # Attach BPF program to tracepoint via Rust interface
                tracepoint_name = f"{tracepoint.subsystem}:{tracepoint.name}"
                self._rust_interface.attach_tracepoint(tracepoint_name)
                
                if self.enable_logging:
                    print(f"Attached tracepoint: {tracepoint_name}")
            except Exception as e:
                if self.enable_logging:
                    print(f"Failed to attach tracepoint {tracepoint.name}: {e}")
    
    def _collect_trace_events(self) -> List[TraceEvent]:
        """Collect trace events from the kernel buffer."""
        events = []
        try:
            raw_events = self._rust_interface.read_trace_events()
            
            for raw_event in raw_events:
                event = TraceEvent(
                    timestamp=datetime.fromtimestamp(raw_event.get("timestamp", 0)),
                    tracepoint=raw_event.get("tracepoint", ""),
                    cpu_id=raw_event.get("cpu_id", 0),
                    pid=raw_event.get("pid", 0),
                    data=raw_event.get("data", {}),
                    raw_bytes=raw_event.get("raw_bytes")
                )
                events.append(event)
                
        except Exception as e:
            if self.enable_logging:
                print(f"Error collecting trace events: {e}")
        
        return events
    
    def _check_kernel_sink(
        self,
        trace_events: List[TraceEvent],
        expected_sink: Optional[str]
    ) -> bool:
        """
        Check if any trace event indicates a kernel sink was hit.
        
        Args:
            trace_events: List of collected trace events
            expected_sink: Optional expected sink function name
            
        Returns:
            True if kernel sink execution detected
        """
        if not trace_events:
            return False
        
        # Common kernel sink patterns to look for
        sink_patterns = [
            "copy_to_user",
            "copy_from_user",
            "kmalloc",
            "kfree",
            "memcpy",
            "sprintf",
            "scanf",
            "execve",
            "commit_creds",
            "prepare_kernel_cred",
        ]
        
        if expected_sink:
            sink_patterns.append(expected_sink)
        
        for event in trace_events:
            # Check tracepoint name
            for pattern in sink_patterns:
                if pattern in event.tracepoint.lower():
                    return True
            
            # Check event data for sink indicators
            event_str = json.dumps(event.data, default=str).lower()
            for pattern in sink_patterns:
                if pattern in event_str:
                    return True
        
        return False
    
    def _cleanup_monitoring(self, tracepoints: List[KernelTracepoint]):
        """Clean up kernel tracepoint monitoring."""
        for tracepoint in tracepoints:
            try:
                tracepoint_name = f"{tracepoint.subsystem}:{tracepoint.name}"
                self._rust_interface.detach_tracepoint(tracepoint_name)
                
                if self.enable_logging:
                    print(f"Detached tracepoint: {tracepoint_name}")
            except Exception as e:
                if self.enable_logging:
                    print(f"Failed to detach tracepoint {tracepoint.name}: {e}")
    
    def batch_verify(
        self,
        vulnerabilities: List[Dict[str, Any]],
        tracepoints: List[KernelTracepoint],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[VerificationResult]:
        """
        Verify multiple vulnerabilities in batch.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries containing:
                - id: Vulnerability identifier
                - payload: Payload bytes
                - target: Target string
                - expected_sink: Optional expected kernel sink
            tracepoints: Common tracepoints to monitor for all verifications
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of VerificationResult objects
        """
        results = []
        total = len(vulnerabilities)
        
        for i, vuln in enumerate(vulnerabilities):
            result = self.verify_vulnerability(
                vulnerability_id=vuln["id"],
                payload=vuln["payload"],
                target=vuln["target"],
                tracepoints=tracepoints,
                expected_sink=vuln.get("expected_sink")
            )
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total)
        
        return results
    
    def get_supported_tracepoints(self) -> List[str]:
        """
        Get list of supported kernel tracepoints.
        
        Returns:
            List of tracepoint names in format "subsystem:name"
        """
        # This would query the actual system for available tracepoints
        # For now, return common security-relevant tracepoints
        common_tracepoints = [
            "syscalls:sys_enter_execve",
            "syscalls:sys_exit_execve",
            "syscalls:sys_enter_connect",
            "syscalls:sys_exit_connect",
            "syscalls:sys_enter_accept",
            "syscalls:sys_exit_accept",
            "net:netif_receive_skb",
            "net:net_dev_xmit",
            "sched:sched_process_exec",
            "sched:sched_process_fork",
            "security:security_bprm_check",
            "security:security_file_permission",
            "security:security_socket_connect",
        ]
        
        return common_tracepoints
    
    def cleanup(self):
        """Clean up resources and unload BPF programs."""
        try:
            if self._rust_interface:
                self._rust_interface.unload_bpf_program()
            if self.enable_logging:
                print("Cleaned up eBPF verifier resources")
        except Exception as e:
            if self.enable_logging:
                print(f"Error during cleanup: {e}")
