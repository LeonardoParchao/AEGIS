"""
Sandbox runner for AEGIS security scanner.

This module spins up Docker containers for dynamic verification, injecting payloads
into isolated targets to prevent collateral damage to actual infrastructure.
It provides safe, isolated environments for vulnerability testing.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import threading
import time
import os


class IsolationLevel(Enum):
    """Levels of isolation for sandbox environments."""
    NETWORK_ISOLATED = "network_isolated"
    PROCESS_ISOLATED = "process_isolated"
    FULL_ISOLATION = "full_isolation"
    SHARED_NETWORK = "shared_network"


@dataclass
class ContainerEnvironment:
    """Configuration for a container environment."""
    image: str
    ports: Dict[str, str] = field(default_factory=dict)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    volumes: Dict[str, str] = field(default_factory=dict)
    command: Optional[str] = None
    working_dir: Optional[str] = None
    network_mode: str = "bridge"
    memory_limit: Optional[str] = None
    cpu_limit: Optional[float] = None


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution."""
    isolation_level: IsolationLevel = IsolationLevel.NETWORK_ISOLATED
    timeout_seconds: int = 30
    auto_cleanup: bool = True
    capture_output: bool = True
    capture_network_traffic: bool = False
    max_containers: int = 5
    log_level: str = "INFO"


@dataclass
class ExecutionResult:
    """Result of payload execution in sandbox."""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_seconds: float
    container_id: str
    network_captured: bool = False
    network_data: Optional[bytes] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SandboxRunner:
    """
    Spin up Docker containers for dynamic verification.
    
    This runner injects payloads into isolated targets to prevent collateral
    damage to the actual infrastructure. It provides safe, isolated environments
    for vulnerability testing using the Docker SDK.
    """
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        """
        Initialize the sandbox runner.
        
        Args:
            config: SandboxConfig with execution parameters
        """
        self.config = config or SandboxConfig()
        self._docker_client = None
        self._active_containers: Dict[str, Any] = {}
        self._container_pool: List[str] = []
        self._lock = threading.Lock()
        
        # Initialize Docker client
        self._initialize_docker()
    
    def _initialize_docker(self):
        """Initialize the Docker SDK client."""
        try:
            import docker
            self._docker_client = docker.from_env()
            
            # Test connection
            self._docker_client.ping()
            
            if self.config.log_level == "DEBUG":
                print("Docker client initialized successfully")
        except ImportError as e:
            raise RuntimeError(
                "Docker SDK not available. "
                "Please install the Docker Python SDK: pip install docker "
                "and ensure Docker is running on your system."
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Docker client: {str(e)}. "
                "Please ensure Docker is running and accessible."
            )
    
    def execute_payload(
        self,
        environment: ContainerEnvironment,
        payload: str,
        target: Optional[str] = None
    ) -> ExecutionResult:
        """
        Execute a payload in an isolated container environment.
        
        Args:
            environment: ContainerEnvironment configuration
            payload: Payload to execute (command or script)
            target: Optional target endpoint within container
            
        Returns:
            ExecutionResult with execution details and output
        """
        start_time = time.time()
        container_id = ""
        error_message = None
        
        try:
            # Pull image if needed
            self._ensure_image(environment.image)
            
            # Configure isolation based on level
            network_config = self._configure_network(environment)
            
            # Run container with payload
            container = self._docker_client.containers.run(
                image=environment.image,
                command=environment.command or payload,
                environment=environment.environment_vars,
                ports=environment.ports,
                volumes=environment.volumes,
                network_mode=network_config,
                mem_limit=environment.memory_limit,
                cpu_quota=int(environment.cpu_limit * 100000) if environment.cpu_limit else None,
                detach=True,
                remove=self.config.auto_cleanup
            )
            
            container_id = container.id
            
            # Track active container
            with self._lock:
                self._active_containers[container_id] = {
                    'container': container,
                    'start_time': datetime.now(),
                    'environment': environment
                }
            
            # Wait for execution or timeout
            result = container.wait(timeout=self.config.timeout_seconds)
            
            # Capture output if configured
            stdout = ""
            stderr = ""
            if self.config.capture_output:
                logs = container.logs(stdout=True, stderr=True)
                stdout = logs.decode('utf-8', errors='ignore')
            
            # Capture network traffic if configured
            network_data = None
            network_captured = False
            if self.config.capture_network_traffic:
                network_data, network_captured = self._capture_network_traffic(container)
            
            execution_time = time.time() - start_time
            
            # Cleanup if configured
            if self.config.auto_cleanup:
                container.stop()
                container.remove(force=True)
                with self._lock:
                    self._active_containers.pop(container_id, None)
            
            return ExecutionResult(
                success=result['StatusCode'] == 0,
                exit_code=result['StatusCode'],
                stdout=stdout,
                stderr=stderr,
                execution_time_seconds=execution_time,
                container_id=container_id,
                network_captured=network_captured,
                network_data=network_data,
                metadata={
                    'image': environment.image,
                    'isolation_level': self.config.isolation_level.value,
                    'payload': payload[:100] + '...' if len(payload) > 100 else payload
                }
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_message = str(e)
            
            if self.config.log_level in ["DEBUG", "INFO"]:
                print(f"Error executing payload: {error_message}")
            
            # Cleanup on error
            if container_id and self.config.auto_cleanup:
                try:
                    container = self._docker_client.containers.get(container_id)
                    container.stop()
                    container.remove(force=True)
                    with self._lock:
                        self._active_containers.pop(container_id, None)
                except Exception as e:
                    if self.config.log_level == "DEBUG":
                        print(f"Error during cleanup: {e}")
            
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=error_message,
                execution_time_seconds=execution_time,
                container_id=container_id,
                error_message=error_message
            )
    
    def _ensure_image(self, image: str):
        """Ensure the Docker image is available locally."""
        try:
            self._docker_client.images.get(image)
        except:
            if self.config.log_level == "DEBUG":
                print(f"Pulling image: {image}")
            self._docker_client.images.pull(image)
    
    def _configure_network(self, environment: ContainerEnvironment) -> str:
        """Configure network based on isolation level."""
        if self.config.isolation_level == IsolationLevel.NETWORK_ISOLATED:
            return "none"
        elif self.config.isolation_level == IsolationLevel.FULL_ISOLATION:
            return "none"
        elif self.config.isolation_level == IsolationLevel.SHARED_NETWORK:
            return "bridge"
        else:
            return environment.network_mode
    
    def _capture_network_traffic(self, container: Any) -> tuple[Optional[bytes], bool]:
        """Capture network traffic from container."""
        import subprocess
        import tempfile

        # Create a temporary file to store the captured traffic
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_path = temp_file.name

        # Run tcpdump to capture traffic
        try:
            network_interface = f'docker{container.attrs["NetworkSettings"]["Networks"]["bridge"]["Index"]}'
            subprocess.run(
                ['tcpdump', '-i', network_interface, '-w', temp_file_path],
                timeout=self.config.timeout_seconds,
                check=True
            )
            network_captured = True
        except subprocess.CalledProcessError as e:
            if self.config.log_level == "DEBUG":
                print(f"tcpdump failed: {e}")
            network_captured = False
        except Exception as e:
            if self.config.log_level == "DEBUG":
                print(f"Network capture error: {e}")
            network_captured = False

        # Read the captured traffic
        captured_data = None
        if network_captured:
            try:
                with open(temp_file_path, 'rb') as temp_file:
                    captured_data = temp_file.read()
            except Exception as e:
                if self.config.log_level == "DEBUG":
                    print(f"Failed to read capture file: {e}")
                network_captured = False

        # Cleanup the temporary file
        try:
            os.unlink(temp_file_path)
        except Exception as e:
            if self.config.log_level == "DEBUG":
                print(f"Failed to cleanup temp file: {e}")

        return captured_data, network_captured
    
    def cleanup_network_capture(self, container_id: str):
        """Cleanup network capture files for a container."""
        import glob
        import os

        # Get the path of the temporary file for this container
        temp_file_pattern = f'/tmp/aegis-scanner-network-capture-{container_id}*'
        temp_file_paths = glob.glob(temp_file_pattern)

        # Remove the temporary file
        for file_path in temp_file_paths:
            try:
                os.unlink(file_path)
            except Exception as e:
                if self.config.log_level == "DEBUG":
                    print(f"Failed to cleanup {file_path}: {e}")
    
    def _post_process_network_capture(self, container_id: str, captured_data: bytes) -> bytes:
        """
        Post-process network capture data for a container.
        
        This implementation removes the pcap file header (first 24 bytes for global header,
        plus 16 bytes per packet header). For simplicity, we remove the first 24 bytes.
        """
        if len(captured_data) > 24:
            return captured_data[24:]
        return captured_data
    
    def cleanup_network_capture_container(self, container_id: str):
        """Cleanup network capture files and data for a container."""
        self.cleanup_network_capture(container_id)
        if container_id in self._active_containers:
            self._active_containers[container_id]['network_data'] = None
        return True
    
    def create_sandbox_pool(
        self,
        environment: ContainerEnvironment,
        count: int = 3
    ) -> List[str]:
        """
        Create a pool of pre-warmed sandbox containers.
        
        Args:
            environment: ContainerEnvironment for pool containers
            count: Number of containers to create
            
        Returns:
            List of container IDs
        """
        container_ids = []
        
        for _ in range(count):
            try:
                self._ensure_image(environment.image)
                
                container = self._docker_client.containers.run(
                    image=environment.image,
                    command="tail -f /dev/null",  # Keep container running
                    environment=environment.environment_vars,
                    network_mode=self._configure_network(environment),
                    mem_limit=environment.memory_limit,
                    detach=True
                )
                
                container_ids.append(container.id)
                
                with self._lock:
                    self._container_pool.append(container.id)
                    self._active_containers[container.id] = {
                        'container': container,
                        'start_time': datetime.now(),
                        'environment': environment,
                        'pooled': True
                    }
                
            except Exception as e:
                if self.config.log_level == "DEBUG":
                    print(f"Error creating pool container: {e}")
        
        return container_ids
    
    def execute_in_pool(
        self,
        payload: str,
        container_id: Optional[str] = None
    ) -> ExecutionResult:
        """
        Execute payload in a pooled container.
        
        Args:
            payload: Payload to execute
            container_id: Specific container ID to use, or None for any available
            
        Returns:
            ExecutionResult
        """
        with self._lock:
            if container_id:
                if container_id not in self._active_containers:
                    return ExecutionResult(
                        success=False,
                        exit_code=-1,
                        stdout="",
                        stderr="Container not found in pool",
                        execution_time_seconds=0,
                        container_id=container_id,
                        error_message="Container not found in pool"
                    )
                container_info = self._active_containers[container_id]
            else:
                # Get any available pooled container
                for cid in self._container_pool:
                    if cid in self._active_containers:
                        container_info = self._active_containers[cid]
                        container_id = cid
                        break
                else:
                    return ExecutionResult(
                        success=False,
                        exit_code=-1,
                        stdout="",
                        stderr="No available containers in pool",
                        execution_time_seconds=0,
                        container_id="",
                        error_message="No available containers in pool"
                    )
        
        container = container_info['container']
        start_time = time.time()
        
        try:
            # Execute payload in container
            exit_code, output = container.exec_run(payload)
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=exit_code == 0,
                exit_code=exit_code,
                stdout=output.decode('utf-8', errors='ignore'),
                stderr="",
                execution_time_seconds=execution_time,
                container_id=container_id,
                metadata={'pooled_execution': True}
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time_seconds=execution_time,
                container_id=container_id,
                error_message=str(e)
            )
    
    def cleanup_pool(self):
        """Clean up all pooled containers."""
        with self._lock:
            for container_id in list(self._container_pool):
                try:
                    if container_id in self._active_containers:
                        container = self._active_containers[container_id]['container']
                        container.stop()
                        container.remove(force=True)
                        self._active_containers.pop(container_id, None)
                except Exception as e:
                    if self.config.log_level == "DEBUG":
                        print(f"Error cleaning up container {container_id}: {e}")
            
            self._container_pool.clear()
    
    def cleanup_all(self):
        """Clean up all active containers."""
        with self._lock:
            for container_id in list(self._active_containers.keys()):
                try:
                    container = self._active_containers[container_id]['container']
                    container.stop()
                    container.remove(force=True)
                except Exception as e:
                    if self.config.log_level == "DEBUG":
                        print(f"Error cleaning up container {container_id}: {e}")
            
            self._active_containers.clear()
            self._container_pool.clear()
    
    def get_active_containers(self) -> List[str]:
        """Get list of active container IDs."""
        with self._lock:
            return list(self._active_containers.keys())
    
    def batch_execute(
        self,
        payloads: List[str],
        environment: ContainerEnvironment,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[ExecutionResult]:
        """
        Execute multiple payloads in sequence.
        
        Args:
            payloads: List of payloads to execute
            environment: ContainerEnvironment for execution
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of ExecutionResult objects
        """
        results = []
        total = len(payloads)
        
        for i, payload in enumerate(payloads):
            result = self.execute_payload(environment, payload)
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total)
        
        return results
    
    def __del__(self):
        """Cleanup on destruction."""
        try:
            self.cleanup_all()
        except Exception as e:
            if self.config.log_level == "DEBUG":
                print(f"Error during destruction cleanup: {e}")
