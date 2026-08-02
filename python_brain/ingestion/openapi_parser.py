"""
OpenAPI/Swagger parser for AEGIS security scanner.

This module parses OpenAPI/Swagger JSON specifications to extract endpoints,
HTTP methods, parameters, and expected response schemas. It also maps
authentication requirements for security testing.
"""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path


class AuthType(Enum):
    """Types of authentication schemes."""
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"


@dataclass
class Parameter:
    """Represents an API parameter."""
    name: str
    param_in: str  # path, query, header, cookie
    required: bool
    param_type: Optional[str] = None
    schema: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    default: Optional[Any] = None


@dataclass
class Response:
    """Represents an API response."""
    status_code: str
    description: str
    content_type: Optional[str] = None
    schema: Optional[Dict[str, Any]] = None
    headers: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Endpoint:
    """Represents an API endpoint."""
    path: str
    method: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: List[Parameter] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    responses: Dict[str, Response] = field(default_factory=dict)
    security: List[Dict[str, List[str]]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class SecurityScheme:
    """Represents a security scheme definition."""
    name: str
    type: AuthType
    scheme: Optional[str] = None
    bearer_format: Optional[str] = None
    description: Optional[str] = None
    flows: Optional[Dict[str, Any]] = None
    location: Optional[str] = None  # for api_key: header, query


@dataclass
class OpenAPISpec:
    """Represents a parsed OpenAPI specification."""
    version: str
    title: str
    description: Optional[str] = None
    base_url: Optional[str] = None
    endpoints: List[Endpoint] = field(default_factory=list)
    security_schemes: Dict[str, SecurityScheme] = field(default_factory=dict)
    global_security: List[Dict[str, List[str]]] = field(default_factory=list)


class OpenAPIParser:
    """
    Parse OpenAPI/Swagger JSON specifications.
    
    Extracts endpoints, HTTP methods, parameters, and expected response schemas.
    Maps authentication requirements for security testing.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the OpenAPI parser.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
    def parse_file(self, file_path: Union[str, Path]) -> OpenAPISpec:
        """
        Parse an OpenAPI specification from a file.
        
        Args:
            file_path: Path to the OpenAPI JSON or YAML file
            
        Returns:
            OpenAPISpec object containing parsed data
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"OpenAPI file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.suffix in ['.json']:
                spec_data = json.load(f)
            else:
                import yaml
                spec_data = yaml.safe_load(f)
        
        return self.parse_spec(spec_data)
    
    def parse_string(self, spec_string: str) -> OpenAPISpec:
        """
        Parse an OpenAPI specification from a string.
        
        Args:
            spec_string: JSON or YAML string containing the spec
            
        Returns:
            OpenAPISpec object containing parsed data
        """
        try:
            spec_data = json.loads(spec_string)
        except json.JSONDecodeError:
            import yaml
            spec_data = yaml.safe_load(spec_string)
        
        return self.parse_spec(spec_data)
    
    def parse_spec(self, spec_data: Dict[str, Any]) -> OpenAPISpec:
        """
        Parse OpenAPI specification data.
        
        Args:
            spec_data: Dictionary containing OpenAPI spec data
            
        Returns:
            OpenAPISpec object containing parsed data
        """
        # Determine OpenAPI version
        openapi_version = spec_data.get('openapi', spec_data.get('swagger', '3.0.0'))
        
        # Extract basic info
        info = spec_data.get('info', {})
        title = info.get('title', 'Unknown API')
        description = info.get('description')
        
        # Extract base URL from servers (OpenAPI 3.x) or host/schemes (Swagger 2.0)
        base_url = self._extract_base_url(spec_data, openapi_version)
        
        # Parse security schemes
        security_schemes = self._parse_security_schemes(spec_data, openapi_version)
        
        # Parse global security requirements
        global_security = spec_data.get('security', [])
        
        # Parse endpoints
        endpoints = self._parse_endpoints(spec_data, openapi_version)
        
        return OpenAPISpec(
            version=openapi_version,
            title=title,
            description=description,
            base_url=base_url,
            endpoints=endpoints,
            security_schemes=security_schemes,
            global_security=global_security
        )
    
    def _extract_base_url(self, spec_data: Dict[str, Any], version: str) -> Optional[str]:
        """Extract base URL from specification."""
        if version.startswith('3.'):
            servers = spec_data.get('servers', [])
            if servers:
                return servers[0].get('url')
        else:
            # Swagger 2.0
            host = spec_data.get('host')
            schemes = spec_data.get('schemes', ['http'])
            base_path = spec_data.get('basePath', '')
            if host:
                return f"{schemes[0]}://{host}{base_path}"
        return None
    
    def _parse_security_schemes(
        self,
        spec_data: Dict[str, Any],
        version: str
    ) -> Dict[str, SecurityScheme]:
        """Parse security scheme definitions."""
        security_schemes = {}
        
        if version.startswith('3.'):
            components = spec_data.get('components', {})
            schemes_data = components.get('securitySchemes', {})
        else:
            # Swagger 2.0
            schemes_data = spec_data.get('securityDefinitions', {})
        
        for name, scheme_data in schemes_data.items():
            auth_type = self._map_auth_type(scheme_data.get('type', 'none'))
            
            security_schemes[name] = SecurityScheme(
                name=name,
                type=auth_type,
                scheme=scheme_data.get('scheme'),
                bearer_format=scheme_data.get('bearerFormat'),
                description=scheme_data.get('description'),
                flows=scheme_data.get('flows'),
                location=scheme_data.get('in')  # for api_key
            )
        
        return security_schemes
    
    def _map_auth_type(self, type_str: str) -> AuthType:
        """Map string to AuthType enum."""
        type_map = {
            'http': AuthType.BEARER,
            'apiKey': AuthType.API_KEY,
            'basic': AuthType.BASIC,
            'oauth2': AuthType.OAUTH2,
            'none': AuthType.NONE,
        }
        return type_map.get(type_str.lower(), AuthType.CUSTOM)
    
    def _parse_endpoints(
        self,
        spec_data: Dict[str, Any],
        version: str
    ) -> List[Endpoint]:
        """Parse all endpoints from the specification."""
        endpoints = []
        paths = spec_data.get('paths', {})
        
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() not in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                    continue
                
                endpoint = self._parse_endpoint(path, method, operation, version)
                endpoints.append(endpoint)
        
        return endpoints
    
    def _parse_endpoint(
        self,
        path: str,
        method: str,
        operation: Dict[str, Any],
        version: str
    ) -> Endpoint:
        """Parse a single endpoint."""
        # Parse parameters
        parameters = []
        for param_data in operation.get('parameters', []):
            param = self._parse_parameter(param_data, version)
            parameters.append(param)
        
        # Parse request body (OpenAPI 3.x only)
        request_body = operation.get('requestBody')
        
        # Parse responses
        responses = {}
        for status_code, response_data in operation.get('responses', {}).items():
            response = self._parse_response(response_data, version)
            responses[status_code] = response
        
        # Parse security requirements
        security = operation.get('security', [])
        
        return Endpoint(
            path=path,
            method=method.upper(),
            operation_id=operation.get('operationId'),
            summary=operation.get('summary'),
            description=operation.get('description'),
            parameters=parameters,
            request_body=request_body,
            responses=responses,
            security=security,
            tags=operation.get('tags', [])
        )
    
    def _parse_parameter(
        self,
        param_data: Dict[str, Any],
        version: str
    ) -> Parameter:
        """Parse a parameter definition."""
        if version.startswith('3.'):
            return Parameter(
                name=param_data['name'],
                param_in=param_data['in'],
                required=param_data.get('required', False),
                param_type=param_data.get('schema', {}).get('type'),
                schema=param_data.get('schema'),
                description=param_data.get('description'),
                default=param_data.get('schema', {}).get('default')
            )
        else:
            # Swagger 2.0
            return Parameter(
                name=param_data['name'],
                param_in=param_data['in'],
                required=param_data.get('required', False),
                param_type=param_data.get('type'),
                schema=param_data.get('schema'),
                description=param_data.get('description'),
                default=param_data.get('default')
            )
    
    def _parse_response(
        self,
        response_data: Dict[str, Any],
        version: str
    ) -> Response:
        """Parse a response definition."""
        content_type = None
        schema = None
        
        if version.startswith('3.'):
            content = response_data.get('content', {})
            if content:
                content_type = list(content.keys())[0]
                schema = content[content_type].get('schema')
        else:
            # Swagger 2.0
            schema = response_data.get('schema')
        
        return Response(
            status_code=str(response_data.get('code', 'default')),
            description=response_data.get('description', ''),
            content_type=content_type,
            schema=schema,
            headers=response_data.get('headers', {})
        )
    
    def get_endpoints_by_tag(self, spec: OpenAPISpec, tag: str) -> List[Endpoint]:
        """Get all endpoints with a specific tag."""
        return [ep for ep in spec.endpoints if tag in ep.tags]
    
    def get_endpoints_by_method(self, spec: OpenAPISpec, method: str) -> List[Endpoint]:
        """Get all endpoints with a specific HTTP method."""
        return [ep for ep in spec.endpoints if ep.method.upper() == method.upper()]
    
    def get_auth_requirements(self, endpoint: Endpoint, spec: OpenAPISpec) -> List[SecurityScheme]:
        """
        Get authentication requirements for an endpoint.
        
        Args:
            endpoint: The endpoint to check
            spec: The OpenAPI specification
            
        Returns:
            List of SecurityScheme objects required for this endpoint
        """
        # Use endpoint-specific security if defined, otherwise use global security
        security_reqs = endpoint.security if endpoint.security else spec.global_security
        
        auth_schemes = []
        for req in security_reqs:
            for scheme_name in req.keys():
                if scheme_name in spec.security_schemes:
                    auth_schemes.append(spec.security_schemes[scheme_name])
        
        return auth_schemes
