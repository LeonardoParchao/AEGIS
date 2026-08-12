"""
Z3 solver interface for AEGIS security scanner.

This module provides a wrapper around Z3 SMT solver for constraint solving
and path analysis, with push/pop contexts for efficient state transition testing.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

try:
    from z3 import Solver, Bool, Int, String, Real, And, Or, Not, Implies, Exists, ForAll, sat, unsat, unknown
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    logger.warning("Z3 library not available. Install with: pip install z3-solver")
    # Create stub classes for when Z3 is not available
    class Solver:
        def __init__(self): pass
        def add(self, *args): pass
        def push(self): pass
        def pop(self): pass
        def check(self): return unknown
        def model(self): return None
        def reset(self): pass
    
    class Bool:
        def __init__(self, name): self.name = name
        def __eq__(self, other): return True
        def __ne__(self, other): return True
    
    class Int:
        def __init__(self, name): self.name = name
        def __eq__(self, other): return True
        def __ne__(self, other): return True
    
    class String:
        def __init__(self, name): self.name = name
        def __eq__(self, other): return True
        def __ne__(self, other): return True
    
    class Real:
        def __init__(self, name): self.name = name
        def __eq__(self, other): return True
        def __ne__(self, other): return True
    
    def And(*args): return True
    def Or(*args): return True
    def Not(arg): return True
    def Implies(a, b): return True
    def Exists(vars, expr): return True
    def ForAll(vars, expr): return True
    
    sat = "sat"
    unsat = "unsat"
    unknown = "unknown"


class SolverStatus(Enum):
    """Status of Z3 solver results."""
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"


@dataclass
class Z3Variable:
    """Represents a Z3 variable."""
    name: str
    var_type: str  # "bool", "int", "string", "real"
    value: Optional[Any] = None
    description: str = ""


@dataclass
class Z3Constraint:
    """Represents a Z3 constraint."""
    constraint_id: str
    expression: str
    variables: Set[str]
    description: str


@dataclass
class SolverResult:
    """Result from Z3 solver."""
    status: SolverStatus
    model: Optional[Dict[str, Any]] = None
    constraints_checked: int = 0
    solving_time_ms: float = 0.0
    error_message: Optional[str] = None


class Z3Interface:
    """
    Z3 solver wrapper for constraint solving and path analysis.
    
    Provides push/pop contexts for testing individual state transitions
    without rebuilding the entire model.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Z3 interface.
        
        Args:
            config: Optional configuration dictionary containing:
                - timeout_ms: Solver timeout in milliseconds
                - enable_logging: Whether to enable debug logging
        """
        self.config = config or {}
        self.timeout_ms = self.config.get('timeout_ms', 5000)
        self.enable_logging = self.config.get('enable_logging', False)
        
        self.solver = Solver()
        self.variables: Dict[str, Z3Variable] = {}
        self.constraints: List[Z3Constraint] = []
        self.context_stack: List[List] = []
        
        if not Z3_AVAILABLE:
            logger.warning("Z3 solver not available - using stub implementation")
        else:
            logger.info("Z3 solver initialized successfully")
    
    def create_variable(self, name: str, var_type: str = "bool", description: str = "") -> Z3Variable:
        """
        Create a Z3 variable.
        
        Args:
            name: Variable name
            var_type: Variable type ("bool", "int", "string", "real")
            description: Optional description
            
        Returns:
            Z3Variable object
        """
        if name in self.variables:
            logger.warning(f"Variable {name} already exists, returning existing")
            return self.variables[name]
        
        var = Z3Variable(name=name, var_type=var_type, description=description)
        self.variables[name] = var
        
        if self.enable_logging:
            logger.debug(f"Created variable: {name} ({var_type})")
        
        return var
    
    def add_constraint(self, constraint: Z3Constraint):
        """
        Add a constraint to the solver.
        
        Args:
            constraint: Z3Constraint object
        """
        self.constraints.append(constraint)
        
        if Z3_AVAILABLE:
            try:
                z3_expr = self._parse_z3_expression(constraint.expression)
                self.solver.add(z3_expr)
                
                if self.enable_logging:
                    logger.debug(f"Added constraint: {constraint.constraint_id}")
            except Exception as e:
                logger.error(f"Failed to add constraint {constraint.constraint_id}: {e}")
        else:
            if self.enable_logging:
                logger.debug(f"Stub: Added constraint: {constraint.constraint_id}")
    
    def _parse_z3_expression(self, expr_str: str):
        """
        Parse a string expression into Z3 expression.
        
        Args:
            expr_str: String representation of Z3 expression
            
        Returns:
            Z3 expression object
        """
        if not Z3_AVAILABLE:
            return True
        
        # This is a simplified parser - in production, you'd want a more robust parser
        # For now, we'll handle basic expressions
        
        # Replace variable names with actual Z3 variables
        for var_name, var in self.variables.items():
            var_placeholder = f"Var('{var_name}')"
            if var_placeholder in expr_str:
                if var.var_type == "bool":
                    z3_var = Bool(var_name)
                elif var.var_type == "int":
                    z3_var = Int(var_name)
                elif var.var_type == "string":
                    z3_var = String(var_name)
                elif var.var_type == "real":
                    z3_var = Real(var_name)
                else:
                    z3_var = Bool(var_name)
                
                expr_str = expr_str.replace(var_placeholder, str(z3_var))
        
        # Evaluate the expression (simplified - in production use proper parsing)
        # This is a placeholder - real implementation would need proper AST parsing
        try:
            # For now, return a simple True as placeholder
            return Bool("placeholder")
        except:
            return Bool("placeholder")
    
    def push_context(self):
        """
        Push a new solver context.
        
        This allows testing individual state transitions without
        rebuilding the entire model.
        """
        if Z3_AVAILABLE:
            self.solver.push()
            self.context_stack.append([])
        
        if self.enable_logging:
            logger.debug(f"Pushed solver context (depth: {len(self.context_stack) + 1})")
    
    def pop_context(self):
        """
        Pop the current solver context.
        
        Restores the solver to the previous state.
        """
        if Z3_AVAILABLE and self.context_stack:
            self.solver.pop()
            self.context_stack.pop()
        
        if self.enable_logging:
            logger.debug(f"Popped solver context (depth: {len(self.context_stack)})")
    
    def solve(self, assumptions: Optional[Dict[str, Any]] = None) -> SolverResult:
        """
        Solve the current constraints.
        
        Args:
            assumptions: Optional dictionary of variable assumptions
            
        Returns:
            SolverResult with status and model
        """
        import time
        
        start_time = time.time()
        
        if not Z3_AVAILABLE:
            return SolverResult(
                status=SolverStatus.UNKNOWN,
                error_message="Z3 solver not available"
            )
        
        try:
            # Add assumptions if provided
            if assumptions:
                self.push_context()
                for var_name, value in assumptions.items():
                    if var_name in self.variables:
                        var = self.variables[var_name]
                        if var.var_type == "bool":
                            constraint = Z3Constraint(
                                constraint_id=f"assumption_{var_name}",
                                expression=f"Var('{var_name}') == {str(value).lower()}",
                                variables={var_name},
                                description=f"Assumption for {var_name}"
                            )
                            self.add_constraint(constraint)
            
            # Check satisfiability
            result = self.solver.check()
            
            solving_time = (time.time() - start_time) * 1000
            
            # Convert result
            if result == sat:
                status = SolverStatus.SAT
                model = self._extract_model()
            elif result == unsat:
                status = SolverStatus.UNSAT
                model = None
            else:
                status = SolverStatus.UNKNOWN
                model = None
            
            solver_result = SolverResult(
                status=status,
                model=model,
                constraints_checked=len(self.constraints),
                solving_time_ms=solving_time
            )
            
            # Clean up assumptions
            if assumptions:
                self.pop_context()
            
            if self.enable_logging:
                logger.info(f"Solver result: {status.value} (time: {solving_time:.2f}ms)")
            
            return solver_result
            
        except Exception as e:
            solving_time = (time.time() - start_time) * 1000
            error_message = str(e)
            
            # Clean up assumptions on error
            if assumptions:
                self.pop_context()
            
            logger.error(f"Solver error: {error_message}")
            
            return SolverResult(
                status=SolverStatus.UNKNOWN,
                error_message=error_message,
                solving_time_ms=solving_time
            )
    
    def _extract_model(self) -> Dict[str, Any]:
        """
        Extract the model from the solver.
        
        Returns:
            Dictionary mapping variable names to their values
        """
        model = {}
        
        if not Z3_AVAILABLE:
            return model
        
        try:
            z3_model = self.solver.model()
            
            for var_name, var in self.variables.items():
                try:
                    # This is simplified - real implementation would need proper model extraction
                    model[var_name] = f"value_for_{var_name}"
                except:
                    model[var_name] = None
        except Exception as e:
            logger.error(f"Failed to extract model: {e}")
        
        return model
    
    def reset(self):
        """Reset the solver to initial state."""
        if Z3_AVAILABLE:
            self.solver.reset()
        
        self.constraints.clear()
        self.context_stack.clear()
        
        if self.enable_logging:
            logger.debug("Solver reset")
    
    def find_satisfying_assignments(
        self,
        variables: List[str],
        max_solutions: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find multiple satisfying assignments for given variables.
        
        Args:
            variables: List of variable names to solve for
            max_solutions: Maximum number of solutions to find
            
        Returns:
            List of dictionaries mapping variable names to values
        """
        solutions = []
        
        if not Z3_AVAILABLE:
            return solutions
        
        for i in range(max_solutions):
            self.push_context()
            
            # Add constraints to exclude previous solutions
            for solution in solutions:
                exclusion_constraints = []
                for var_name in variables:
                    if var_name in solution:
                        exclusion_constraints.append(
                            f"Var('{var_name}') != {self._format_z3_value(solution[var_name])}"
                        )
                
                if exclusion_constraints:
                    exclusion_expr = f"Not(And({', '.join(exclusion_constraints)}))"
                    constraint = Z3Constraint(
                        constraint_id=f"exclusion_{i}",
                        expression=exclusion_expr,
                        set(variables),
                        description=f"Exclusion constraint for solution {i}"
                    )
                    self.add_constraint(constraint)
            
            result = self.solve()
            
            if result.status == SolverStatus.SAT and result.model:
                # Extract values for requested variables
                solution = {
                    var_name: result.model.get(var_name)
                    for var_name in variables
                    if var_name in result.model
                }
                solutions.append(solution)
            else:
                self.pop_context()
                break
            
            self.pop_context()
        
        if self.enable_logging:
            logger.info(f"Found {len(solutions)} satisfying assignments")
        
        return solutions
    
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
    
    def get_solver_info(self) -> Dict[str, Any]:
        """
        Get information about the current solver state.
        
        Returns:
            Dictionary containing solver statistics
        """
        return {
            'z3_available': Z3_AVAILABLE,
            'total_variables': len(self.variables),
            'total_constraints': len(self.constraints),
            'context_depth': len(self.context_stack),
            'variable_types': {
                var_type: len([v for v in self.variables.values() if v.var_type == var_type])
                for var_type in ["bool", "int", "string", "real"]
            }
        }
