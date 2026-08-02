"""
Proof validator for AEGIS security scanner.

This module cross-references eBPF kernel traces with expected sinks to validate
vulnerability proofs. It discards static analysis anomalies that do not result in
proven kernel-level sink execution, ensuring mathematical rigor in vulnerability confirmation.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import re


class SinkType(Enum):
    """Types of kernel sinks that indicate vulnerability exploitation."""
    MEMORY_CORRUPTION = "memory_corruption"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_LEAK = "information_leak"
    DENIAL_OF_SERVICE = "denial_of_service"
    ARBITRARY_CODE_EXECUTION = "arbitrary_code_execution"
    CONTROL_FLOW_HIJACK = "control_flow_hijack"


@dataclass
class KernelSink:
    """Represents a kernel sink that indicates vulnerability exploitation."""
    name: str
    sink_type: SinkType
    subsystem: str
    required_args: List[str] = field(default_factory=list)
    confidence_threshold: float = 0.8
    description: Optional[str] = None


@dataclass
class TraceAnalysis:
    """Analysis result of kernel trace events."""
    trace_events_count: int
    matched_sinks: List[KernelSink]
    unmatched_sinks: List[KernelSink]
    confidence_score: float
    execution_path: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of vulnerability proof validation."""
    vulnerability_id: str
    valid: bool
    confidence: float
    proven_sinks: List[KernelSink]
    rejected_anomalies: List[str]
    analysis: TraceAnalysis
    timestamp: datetime = field(default_factory=datetime.now)
    reason: Optional[str] = None


class ProofValidator:
    """
    Cross-reference eBPF kernel traces with expected sinks.
    
    This validator discards static analysis anomalies that do not result in
    proven kernel-level sink execution, ensuring mathematical rigor in
    vulnerability confirmation.
    """
    
    # Predefined kernel sinks with their characteristics
    KERNEL_SINKS = {
        "copy_to_user": KernelSink(
            name="copy_to_user",
            sink_type=SinkType.INFORMATION_LEAK,
            subsystem="kernel",
            required_args=["to", "from", "n"],
            confidence_threshold=0.9,
            description="Copy data from kernel space to user space"
        ),
        "copy_from_user": KernelSink(
            name="copy_from_user",
            sink_type=SinkType.MEMORY_CORRUPTION,
            subsystem="kernel",
            required_args=["to", "from", "n"],
            confidence_threshold=0.9,
            description="Copy data from user space to kernel space"
        ),
        "kmalloc": KernelSink(
            name="kmalloc",
            sink_type=SinkType.MEMORY_CORRUPTION,
            subsystem="mm",
            required_args=["size", "flags"],
            confidence_threshold=0.7,
            description="Kernel memory allocation"
        ),
        "kfree": KernelSink(
            name="kfree",
            sink_type=SinkType.MEMORY_CORRUPTION,
            subsystem="mm",
            required_args=["ptr"],
            confidence_threshold=0.7,
            description="Kernel memory deallocation"
        ),
        "memcpy": KernelSink(
            name="memcpy",
            sink_type=SinkType.MEMORY_CORRUPTION,
            subsystem="kernel",
            required_args=["dest", "src", "count"],
            confidence_threshold=0.6,
            description="Memory copy operation"
        ),
        "commit_creds": KernelSink(
            name="commit_creds",
            sink_type=SinkType.PRIVILEGE_ESCALATION,
            subsystem="security",
            required_args=["new"],
            confidence_threshold=0.95,
            description="Commit new credentials to task"
        ),
        "prepare_kernel_cred": KernelSink(
            name="prepare_kernel_cred",
            sink_type=SinkType.PRIVILEGE_ESCALATION,
            subsystem="security",
            required_args=["task"],
            confidence_threshold=0.95,
            description="Prepare kernel credentials for task"
        ),
        "execve": KernelSink(
            name="execve",
            sink_type=SinkType.ARBITRARY_CODE_EXECUTION,
            subsystem="syscalls",
            required_args=["filename", "argv", "envp"],
            confidence_threshold=0.9,
            description="Execute a program"
        ),
        "schedule": KernelSink(
            name="schedule",
            sink_type=SinkType.CONTROL_FLOW_HIJACK,
            subsystem="sched",
            required_args=[],
            confidence_threshold=0.5,
            description="Process scheduler"
        ),
        "panic": KernelSink(
            name="panic",
            sink_type=SinkType.DENIAL_OF_SERVICE,
            subsystem="kernel",
            required_args=["fmt"],
            confidence_threshold=1.0,
            description="Kernel panic"
        ),
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the proof validator.
        
        Args:
            config: Optional configuration dictionary containing:
                - min_confidence: Minimum confidence threshold for validation
                - enable_strict_validation: Enable strict validation mode
                - custom_sinks: Custom kernel sinks to add
        """
        self.config = config or {}
        self.min_confidence = self.config.get('min_confidence', 0.8)
        self.enable_strict_validation = self.config.get('enable_strict_validation', True)
        
        # Add custom sinks if provided
        custom_sinks = self.config.get('custom_sinks', [])
        for sink in custom_sinks:
            self.KERNEL_SINKS[sink.name] = sink
    
    def validate_proof(
        self,
        vulnerability_id: str,
        trace_events: List[Any],
        expected_sinks: List[str],
        static_analysis_findings: Optional[List[str]] = None
    ) -> ValidationResult:
        """
        Validate a vulnerability proof by cross-referencing traces with expected sinks.
        
        Args:
            vulnerability_id: Unique identifier for the vulnerability
            trace_events: List of trace events from eBPF monitoring
            expected_sinks: List of expected kernel sink names
            static_analysis_findings: Optional list of static analysis findings to validate
            
        Returns:
            ValidationResult with validity status and detailed analysis
        """
        # Analyze trace events for kernel sinks
        analysis = self._analyze_traces(trace_events, expected_sinks)
        
        # Validate against static analysis findings
        rejected_anomalies = []
        if static_analysis_findings:
            rejected_anomalies = self._validate_static_analysis(
                static_analysis_findings,
                analysis.matched_sinks
            )
        
        # Determine overall validity
        valid = self._determine_validity(analysis, rejected_anomalies)
        
        confidence = analysis.confidence_score
        
        reason = self._generate_reason(valid, analysis, rejected_anomalies)
        
        return ValidationResult(
            vulnerability_id=vulnerability_id,
            valid=valid,
            confidence=confidence,
            proven_sinks=analysis.matched_sinks,
            rejected_anomalies=rejected_anomalies,
            analysis=analysis,
            reason=reason
        )
    
    def _analyze_traces(
        self,
        trace_events: List[Any],
        expected_sinks: List[str]
    ) -> TraceAnalysis:
        """Analyze trace events for kernel sink execution."""
        matched_sinks = []
        unmatched_sinks = []
        execution_path = []
        anomalies = []
        
        # Normalize expected sinks
        expected_set = set(expected_sinks)
        
        # Extract execution path from trace events
        for event in trace_events:
            if hasattr(event, 'tracepoint'):
                execution_path.append(event.tracepoint)
            elif isinstance(event, dict) and 'tracepoint' in event:
                execution_path.append(event['tracepoint'])
        
        # Check for kernel sinks in trace events
        trace_data = self._extract_trace_data(trace_events)
        
        for sink_name, sink in self.KERNEL_SINKS.items():
            if self._check_sink_in_traces(sink, trace_data):
                matched_sinks.append(sink)
            elif sink_name in expected_set:
                unmatched_sinks.append(sink)
        
        # Detect anomalies in execution path
        anomalies = self._detect_anomalies(execution_path, matched_sinks)
        
        # Calculate confidence score
        confidence = self._calculate_confidence(
            matched_sinks,
            expected_sinks,
            len(trace_events)
        )
        
        return TraceAnalysis(
            trace_events_count=len(trace_events),
            matched_sinks=matched_sinks,
            unmatched_sinks=unmatched_sinks,
            confidence_score=confidence,
            execution_path=execution_path,
            anomalies=anomalies,
            metadata={
                "expected_sinks": expected_sinks,
                "trace_data_sample": trace_data[:5] if trace_data else []
            }
        )
    
    def _extract_trace_data(self, trace_events: List[Any]) -> List[Dict[str, Any]]:
        """Extract structured data from trace events."""
        trace_data = []
        
        for event in trace_events:
            if hasattr(event, 'data'):
                trace_data.append({
                    'tracepoint': getattr(event, 'tracepoint', ''),
                    'data': event.data
                })
            elif isinstance(event, dict):
                trace_data.append({
                    'tracepoint': event.get('tracepoint', ''),
                    'data': event.get('data', {})
                })
        
        return trace_data
    
    def _check_sink_in_traces(
        self,
        sink: KernelSink,
        trace_data: List[Dict[str, Any]]
    ) -> bool:
        """Check if a kernel sink appears in trace data."""
        for trace in trace_data:
            # Check tracepoint name
            if sink.name in trace['tracepoint'].lower():
                return True
            
            # Check trace data for sink indicators
            trace_str = str(trace['data']).lower()
            if sink.name in trace_str:
                # Check for required arguments
                if self._check_required_args(sink, trace['data']):
                    return True
        
        return False
    
    def _check_required_args(
        self,
        sink: KernelSink,
        trace_data: Dict[str, Any]
    ) -> bool:
        """Check if required arguments are present in trace data."""
        if not sink.required_args:
            return True
        
        trace_str = str(trace_data).lower()
        for arg in sink.required_args:
            if arg.lower() not in trace_str:
                return False
        
        return True
    
    def _detect_anomalies(
        self,
        execution_path: List[str],
        matched_sinks: List[KernelSink]
    ) -> List[str]:
        """Detect anomalies in the execution path."""
        anomalies = []
        
        # Check for unexpected execution patterns
        if len(execution_path) == 0 and matched_sinks:
            anomalies.append("Trace events empty but sinks matched")
        
        # Check for impossible execution sequences
        for i in range(len(execution_path) - 1):
            current = execution_path[i]
            next_trace = execution_path[i + 1]
            
            # Example anomaly: privilege escalation without proper context
            if "commit_creds" in current and "prepare_kernel_cred" not in execution_path[:i]:
                anomalies.append(f"Privilege escalation without credential preparation at {i}")
        
        return anomalies
    
    def _calculate_confidence(
        self,
        matched_sinks: List[KernelSink],
        expected_sinks: List[str],
        trace_count: int
    ) -> float:
        """Calculate overall confidence score."""
        if not expected_sinks:
            return 0.0
        
        # Base confidence from matched sinks
        matched_count = len(matched_sinks)
        expected_count = len(expected_sinks)
        
        if expected_count == 0:
            return 0.0
        
        match_ratio = matched_count / expected_count
        
        # Weight by sink confidence thresholds
        sink_confidence = 0.0
        for sink in matched_sinks:
            sink_confidence += sink.confidence_threshold
        
        if matched_sinks:
            sink_confidence /= len(matched_sinks)
        
        # Combine factors
        confidence = (match_ratio * 0.6) + (sink_confidence * 0.4)
        
        # Boost confidence if we have good trace coverage
        if trace_count > 10:
            confidence = min(confidence * 1.1, 1.0)
        
        return round(confidence, 3)
    
    def _validate_static_analysis(
        self,
        static_findings: List[str],
        proven_sinks: List[KernelSink]
    ) -> List[str]:
        """Validate static analysis findings against proven sinks."""
        rejected = []
        
        proven_sink_names = {sink.name for sink in proven_sinks}
        
        for finding in static_findings:
            # Check if finding corresponds to a proven sink
            finding_lower = finding.lower()
            is_proven = any(
                sink_name in finding_lower
                for sink_name in proven_sink_names
            )
            
            if not is_proven:
                rejected.append(finding)
        
        return rejected
    
    def _determine_validity(
        self,
        analysis: TraceAnalysis,
        rejected_anomalies: List[str]
    ) -> bool:
        """Determine if the proof is valid."""
        # Must meet minimum confidence threshold
        if analysis.confidence_score < self.min_confidence:
            return False
        
        # In strict mode, require at least one matched sink
        if self.enable_strict_validation and not analysis.matched_sinks:
            return False
        
        # Should not have critical anomalies
        critical_anomalies = [
            a for a in analysis.anomalies
            if "impossible" in a.lower() or "invalid" in a.lower()
        ]
        if critical_anomalies:
            return False
        
        return True
    
    def _generate_reason(
        self,
        valid: bool,
        analysis: TraceAnalysis,
        rejected_anomalies: List[str]
    ) -> str:
        """Generate human-readable reason for validation result."""
        if valid:
            sink_names = [s.name for s in analysis.matched_sinks]
            return (
                f"Proof validated with {analysis.confidence_score:.2f} confidence. "
                f"Proven sinks: {', '.join(sink_names)}. "
                f"Analyzed {analysis.trace_events_count} trace events."
            )
        else:
            reasons = []
            if analysis.confidence_score < self.min_confidence:
                reasons.append(
                    f"Confidence {analysis.confidence_score:.2f} below threshold {self.min_confidence}"
                )
            if not analysis.matched_sinks and self.enable_strict_validation:
                reasons.append("No kernel sinks matched in strict mode")
            if analysis.anomalies:
                reasons.append(f"Anomalies detected: {', '.join(analysis.anomalies)}")
            if rejected_anomalies:
                reasons.append(
                    f"Rejected {len(rejected_anomalies)} static analysis findings"
                )
            
            return "; ".join(reasons) if reasons else "Validation failed"
    
    def add_custom_sink(self, sink: KernelSink):
        """Add a custom kernel sink definition."""
        self.KERNEL_SINKS[sink.name] = sink
    
    def get_available_sinks(self) -> List[KernelSink]:
        """Get list of available kernel sinks."""
        return list(self.KERNEL_SINKS.values())
    
    def batch_validate(
        self,
        vulnerabilities: List[Dict[str, Any]],
        progress_callback: Optional[callable] = None
    ) -> List[ValidationResult]:
        """
        Validate multiple vulnerability proofs in batch.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries containing:
                - id: Vulnerability identifier
                - trace_events: List of trace events
                - expected_sinks: List of expected sink names
                - static_analysis_findings: Optional static analysis findings
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of ValidationResult objects
        """
        results = []
        total = len(vulnerabilities)
        
        for i, vuln in enumerate(vulnerabilities):
            result = self.validate_proof(
                vulnerability_id=vuln["id"],
                trace_events=vuln["trace_events"],
                expected_sinks=vuln["expected_sinks"],
                static_analysis_findings=vuln.get("static_analysis_findings")
            )
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total)
        
        return results
