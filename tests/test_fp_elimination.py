"""
False Positive Elimination Tests for AEGIS Scanner

These tests verify that the eBPF verifier correctly suppresses false positives
by distinguishing between detected vulnerabilities and actual exploitable conditions.
"""

import pytest
from python_brain.verification.ebpf_verifier import EBPFVerifier, KernelTracepoint
from python_brain.cognitive.smt_solver.z3_interface import Z3Interface


def test_z3_constraint_false_positive():
    """Test that Z3 solver correctly identifies unsatisfiable constraints."""
    z3_solver = Z3Interface()
    
    # Create a scenario that looks like a vulnerability but is actually unsatisfiable
    z3_solver.create_variable("admin_access", "bool")
    z3_solver.create_variable("user_role", "string")
    
    from python_brain.cognitive.smt_solver.z3_interface import Z3Constraint
    
    # Add impossible constraints
    constraint = Z3Constraint(
        constraint_id="impossible_bypass",
        expression="And(Var('admin_access'), Not(Var('admin_access')))",
        variables={"admin_access"},
        description="Impossible constraint that should be unsatisfiable"
    )
    
    z3_solver.add_constraint(constraint)
    result = z3_solver.solve()
    
    # This should be unsatisfiable (false positive)
    assert result.status.value == "unsat"


def test_ebpf_verifier_suppresses_false_positive():
    """Test that eBPF verifier correctly suppresses false positives."""
    try:
        verifier = EBPFVerifier(config={'skip_capability_check': True})
        
        # Create a payload that would be flagged by static analysis
        payload = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        
        # Define tracepoints for admin access
        tracepoints = [
            KernelTracepoint("sys_enter_accept", "syscalls"),
            KernelTracepoint("security_socket_connect", "security")
        ]
        
        # This should return not confirmed since it's a false positive
        result = verifier.verify_vulnerability(
            vulnerability_id="test_false_positive",
            payload=payload,
            target="http://localhost/admin",
            tracepoints=tracepoints,
            expected_sink="commit_creds"
        )
        
        # False positive should not be confirmed
        assert not result.confirmed
        assert result.confidence < 0.5
        
    except RuntimeError as e:
        # eBPF not available, skip test
        pytest.skip(f"eBPF not available: {e}")


def test_business_logic_bypass_validation():
    """Test that business logic analyzer correctly validates state transitions."""
    from python_brain.cognitive.smt_solver.business_logic import BusinessLogicAnalyzer
    
    analyzer = BusinessLogicAnalyzer()
    
    # Add states and transitions
    analyzer.add_state("guest")
    analyzer.add_state("user")
    analyzer.add_state("admin")
    
    analyzer.add_transition("guest", "user")
    analyzer.add_transition("user", "admin")
    
    # Test invalid transition (guest -> admin without authentication)
    is_valid, violations = analyzer.validate_transition(
        source_state="guest",
        target_state="admin",
        current_conditions={"authenticated": False}
    )
    
    # This should be invalid with violations
    assert not is_valid
    assert len(violations) > 0
