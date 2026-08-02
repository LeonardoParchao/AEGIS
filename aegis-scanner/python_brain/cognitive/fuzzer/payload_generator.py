"""
SMT-guided payload generator for AEGIS security scanner.

This module takes logical bypass paths calculated by Z3 and formats them
into HTTP requests or network packets for the Rust engines to fire.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
import json
import struct


class PayloadType(Enum):
    """Types of payloads that can be generated."""
    HTTP_REQUEST = "http_request"
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    HTTP_PUT = "http_put"
    HTTP_DELETE = "http_delete"
    TCP_PACKET = "tcp_packet"
    UDP_PACKET = "udp_packet"
    RAW_BYTES = "raw_bytes"
    JSON_RPC = "json_rpc"
    GRAPHQL = "graphql"


@dataclass
class BypassPath:
    """Represents a logical bypass path from Z3 solver."""
    target_state: str
    constraints: Dict[str, Any]
    required_parameters: Dict[str, Any]
    path_conditions: List[str]
    confidence: float = 1.0


@dataclass
class GeneratedPayload:
    """Represents a generated payload ready for execution."""
    payload_type: PayloadType
    data: Union[bytes, str, Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)
    target: Optional[str] = None
    method: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


class PayloadGenerator:
    """
    Generate SMT-guided payloads from Z3 solver results.
    
    Takes logical bypass paths calculated by Z3 and formats them into
    HTTP requests or network packets for the Rust engines to fire.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the payload generator.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.default_headers = {
            'User-Agent': 'AEGIS-Scanner/1.0',
            'Accept': '*/*',
        }
        
    def generate_from_bypass_path(
        self,
        bypass_path: BypassPath,
        payload_type: PayloadType = PayloadType.HTTP_REQUEST,
        target: Optional[str] = None
    ) -> GeneratedPayload:
        """
        Generate a payload from a Z3 bypass path.
        
        Args:
            bypass_path: The bypass path from Z3 solver
            payload_type: Type of payload to generate
            target: Target URL or endpoint
            
        Returns:
            GeneratedPayload ready for execution
        """
        if payload_type in [PayloadType.HTTP_REQUEST, PayloadType.HTTP_GET, PayloadType.HTTP_POST]:
            return self._generate_http_payload(bypass_path, payload_type, target)
        elif payload_type in [PayloadType.TCP_PACKET, PayloadType.UDP_PACKET]:
            return self._generate_network_payload(bypass_path, payload_type)
        elif payload_type == PayloadType.JSON_RPC:
            return self._generate_json_rpc_payload(bypass_path, target)
        elif payload_type == PayloadType.GRAPHQL:
            return self._generate_graphql_payload(bypass_path, target)
        else:
            return self._generate_raw_payload(bypass_path)
    
    def _generate_http_payload(
        self,
        bypass_path: BypassPath,
        payload_type: PayloadType,
        target: Optional[str]
    ) -> GeneratedPayload:
        """Generate HTTP request payload."""
        method = self._get_http_method(payload_type)
        
        # Build parameters from bypass path constraints
        params = {}
        for key, value in bypass_path.required_parameters.items():
            params[key] = self._format_value(value)
        
        # Add constraint-based parameters
        for key, value in bypass_path.constraints.items():
            if key not in params:
                params[key] = self._format_value(value)
        
        headers = self.default_headers.copy()
        if payload_type in [PayloadType.HTTP_POST, PayloadType.HTTP_PUT]:
            headers['Content-Type'] = 'application/json'
        
        return GeneratedPayload(
            payload_type=payload_type,
            data={
                'method': method,
                'target': target,
                'params': params,
                'headers': headers,
            },
            metadata={
                'bypass_target': bypass_path.target_state,
                'confidence': bypass_path.confidence,
                'path_conditions': bypass_path.path_conditions,
            },
            target=target,
            method=method,
            headers=headers
        )
    
    def _generate_network_payload(
        self,
        bypass_path: BypassPath,
        payload_type: PayloadType
    ) -> GeneratedPayload:
        """Generate network packet payload."""
        # Extract byte sequences from constraints
        raw_data = bytearray()
        
        for key, value in bypass_path.required_parameters.items():
            if isinstance(value, (int, bytes)):
                raw_data.extend(self._value_to_bytes(value))
        
        # Add constraint-based data
        for key, value in bypass_path.constraints.items():
            if isinstance(value, (int, bytes)):
                raw_data.extend(self._value_to_bytes(value))
        
        return GeneratedPayload(
            payload_type=payload_type,
            data=bytes(raw_data),
            metadata={
                'bypass_target': bypass_path.target_state,
                'confidence': bypass_path.confidence,
                'protocol': payload_type.value,
            }
        )
    
    def _generate_json_rpc_payload(
        self,
        bypass_path: BypassPath,
        target: Optional[str]
    ) -> GeneratedPayload:
        """Generate JSON-RPC payload."""
        rpc_payload = {
            'jsonrpc': '2.0',
            'method': bypass_path.target_state,
            'params': bypass_path.required_parameters,
            'id': 1
        }
        
        return GeneratedPayload(
            payload_type=PayloadType.JSON_RPC,
            data=rpc_payload,
            metadata={
                'bypass_target': bypass_path.target_state,
                'confidence': bypass_path.confidence,
            },
            target=target,
            headers={'Content-Type': 'application/json'}
        )
    
    def _generate_graphql_payload(
        self,
        bypass_path: BypassPath,
        target: Optional[str]
    ) -> GeneratedPayload:
        """Generate GraphQL payload."""
        # Build GraphQL query/mutation from bypass path
        operation_type = 'mutation' if bypass_path.target_state.endswith('_modify') else 'query'
        
        fields = []
        for param in bypass_path.required_parameters.keys():
            fields.append(param)
        
        graphql_payload = {
            'query': f'{operation_type} {{ {bypass_path.target_state}({self._build_graphql_args(bypass_path.required_parameters)}) {{ {", ".join(fields)} }} }}',
            'variables': bypass_path.required_parameters
        }
        
        return GeneratedPayload(
            payload_type=PayloadType.GRAPHQL,
            data=graphql_payload,
            metadata={
                'bypass_target': bypass_path.target_state,
                'confidence': bypass_path.confidence,
            },
            target=target,
            headers={'Content-Type': 'application/json'}
        )
    
    def _generate_raw_payload(self, bypass_path: BypassPath) -> GeneratedPayload:
        """Generate raw byte payload."""
        raw_data = bytearray()
        
        for value in bypass_path.required_parameters.values():
            raw_data.extend(self._value_to_bytes(value))
        
        for value in bypass_path.constraints.values():
            raw_data.extend(self._value_to_bytes(value))
        
        return GeneratedPayload(
            payload_type=PayloadType.RAW_BYTES,
            data=bytes(raw_data),
            metadata={
                'bypass_target': bypass_path.target_state,
                'confidence': bypass_path.confidence,
            }
        )
    
    def _get_http_method(self, payload_type: PayloadType) -> str:
        """Map payload type to HTTP method."""
        mapping = {
            PayloadType.HTTP_REQUEST: 'GET',
            PayloadType.HTTP_GET: 'GET',
            PayloadType.HTTP_POST: 'POST',
            PayloadType.HTTP_PUT: 'PUT',
            PayloadType.HTTP_DELETE: 'DELETE',
        }
        return mapping.get(payload_type, 'GET')
    
    def _format_value(self, value: Any) -> Any:
        """Format a value for payload inclusion."""
        if isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, (int, float)):
            return value
        elif isinstance(value, bytes):
            return value.hex()
        else:
            return str(value)
    
    def _value_to_bytes(self, value: Any) -> bytes:
        """Convert a value to bytes."""
        if isinstance(value, bytes):
            return value
        elif isinstance(value, int):
            return struct.pack('>Q', value)
        elif isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, bool):
            return b'\x01' if value else b'\x00'
        else:
            return str(value).encode('utf-8')
    
    def _build_graphql_args(self, params: Dict[str, Any]) -> str:
        """Build GraphQL argument string from parameters."""
        args = []
        for key, value in params.items():
            formatted_value = json.dumps(value) if isinstance(value, (dict, list)) else str(value)
            args.append(f'{key}: {formatted_value}')
        return ', '.join(args)
    
    def batch_generate(
        self,
        bypass_paths: List[BypassPath],
        payload_type: PayloadType = PayloadType.HTTP_REQUEST,
        target: Optional[str] = None
    ) -> List[GeneratedPayload]:
        """
        Generate multiple payloads from a list of bypass paths.
        
        Args:
            bypass_paths: List of bypass paths from Z3 solver
            payload_type: Type of payload to generate
            target: Target URL or endpoint
            
        Returns:
            List of GeneratedPayload objects
        """
        return [
            self.generate_from_bypass_path(bp, payload_type, target)
            for bp in bypass_paths
        ]
    
    def serialize_payload(self, payload: GeneratedPayload) -> bytes:
        """
        Serialize a payload for transmission to Rust engines.
        
        Args:
            payload: The payload to serialize
            
        Returns:
            Serialized bytes
        """
        payload_dict = {
            'type': payload.payload_type.value,
            'data': payload.data,
            'metadata': payload.metadata,
            'target': payload.target,
            'method': payload.method,
            'headers': payload.headers,
        }
        return json.dumps(payload_dict).encode('utf-8')
    
    def deserialize_payload(self, data: bytes) -> GeneratedPayload:
        """
        Deserialize a payload from bytes.
        
        Args:
            data: Serialized payload bytes
            
        Returns:
            GeneratedPayload object
        """
        payload_dict = json.loads(data.decode('utf-8'))
        return GeneratedPayload(
            payload_type=PayloadType(payload_dict['type']),
            data=payload_dict['data'],
            metadata=payload_dict.get('metadata', {}),
            target=payload_dict.get('target'),
            method=payload_dict.get('method'),
            headers=payload_dict.get('headers', {})
        )
