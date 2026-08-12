"""
Flask API Server for AEGIS Scanner GUI

Provides REST endpoints for the web interface to interact with the scanner.
"""

import asyncio
import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import uuid

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.exceptions import Unauthorized

from python_brain.orchestrator.scanner_manager import (
    ScannerManager,
    ScanConfig,
    ScanPhase,
    ScannerStatus
)
from python_brain.orchestrator.target_state import TargetStateManager
from python_brain.ingestion.openapi_parser import OpenAPIParser
from python_brain.ingestion.pcap_ingestor import PcapIngestor
from python_brain.reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# Configure CORS with restricted origins for security
# Set CORS_ALLOWED_ORIGINS environment variable to comma-separated list of allowed origins
# Default: localhost and 127.0.0.1 on port 5000 for development
allowed_origins = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000').split(',')
CORS(app, origins=allowed_origins)
socketio = SocketIO(app, cors_allowed_origins=allowed_origins, async_mode='threading')

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # HTTP Strict Transport Security (HSTS) - only enable in production with HTTPS
    if os.environ.get('ENABLE_HSTS', 'false').lower() == 'true':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Prevent content type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Enable browser XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy (basic - can be customized via environment variable)
    csp = os.environ.get('CSP_POLICY', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
    response.headers['Content-Security-Policy'] = csp
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

# Authentication configuration
API_KEY = os.environ.get('AEGIS_API_KEY')
if not API_KEY:
    logger.warning("AEGIS_API_KEY not set - authentication disabled. Set this environment variable for production.")
    API_KEY = None

def require_auth(f):
    """Decorator to require API key authentication for endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if API_KEY is None:
            # Authentication disabled in development
            return f(*args, **kwargs)
        
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header required'}), 401
        
        # Support both Bearer token and direct API key
        if auth_header.startswith('Bearer '):
            provided_key = auth_header[7:]
        else:
            provided_key = auth_header
        
        if provided_key != API_KEY:
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    return decorated

def rate_limit(f):
    """Decorator to apply rate limiting to endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        allowed, error_msg = check_rate_limit(client_ip)
        if not allowed:
            return jsonify({'error': error_msg}), 429
        return f(*args, **kwargs)
    return decorated

# Global scanner instance
scanner: Optional[ScannerManager] = None
state_manager: Optional[TargetStateManager] = None
current_scan_id: Optional[str] = None
scan_results: Dict[str, Any] = {}

# Rate limiting and resource management
MAX_CONCURRENT_SCANS = int(os.environ.get('AEGIS_MAX_CONCURRENT_SCANS', '2'))
active_scans_count = 0
scan_lock = threading.Lock()

# Rate limiting: max requests per minute per IP
RATE_LIMIT_REQUESTS = int(os.environ.get('AEGIS_RATE_LIMIT_REQUESTS', '30'))
RATE_LIMIT_WINDOW = 60  # seconds
request_tracker = defaultdict(list)  # IP -> list of timestamps

def check_rate_limit(ip: str) -> Tuple[bool, str]:
    """
    Check if the IP has exceeded the rate limit.
    
    Args:
        ip: The client IP address
        
    Returns:
        Tuple of (allowed, error_message)
    """
    current_time = time.time()
    
    # Clean up old requests outside the time window
    request_tracker[ip] = [
        timestamp for timestamp in request_tracker[ip]
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]
    
    # Check if limit exceeded
    if len(request_tracker[ip]) >= RATE_LIMIT_REQUESTS:
        return False, f"Rate limit exceeded: max {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds"
    
    # Add current request
    request_tracker[ip].append(current_time)
    return True, ""

def can_start_scan() -> Tuple[bool, str]:
    """
    Check if a new scan can be started based on concurrent scan limits.
    
    Returns:
        Tuple of (can_start, error_message)
    """
    with scan_lock:
        if active_scans_count >= MAX_CONCURRENT_SCANS:
            return False, f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached. Please wait for current scans to complete."
        active_scans_count += 1
        return True, ""

def decrement_active_scans():
    """Decrement the active scans count."""
    global active_scans_count
    with scan_lock:
        active_scans_count = max(0, active_scans_count - 1)

# Security: Define allowed base directory for file inputs
ALLOWED_INPUT_DIR = os.environ.get('AEGIS_ALLOWED_INPUT_DIR', os.getcwd())

def validate_file_path(file_path: str) -> Tuple[bool, str]:
    """
    Validate that a file path is within the allowed directory to prevent path traversal attacks.
    
    Args:
        file_path: The file path to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Resolve the absolute path
        abs_path = Path(file_path).resolve()
        
        # Resolve the allowed directory absolute path
        allowed_dir = Path(ALLOWED_INPUT_DIR).resolve()
        
        # Check if the resolved path is within the allowed directory
        try:
            abs_path.relative_to(allowed_dir)
        except ValueError:
            return False, f"File path must be within allowed directory: {allowed_dir}"
        
        # Check if file exists
        if not abs_path.exists():
            return False, f"File not found: {file_path}"
        
        # Check if it's a file (not a directory)
        if not abs_path.is_file():
            return False, f"Path is not a file: {file_path}"
        
        return True, ""
        
    except Exception as e:
        return False, f"Invalid file path: {str(e)}"

def validate_scan_config(data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate scan configuration parameters to prevent injection and ensure safe values.
    
    Args:
        data: The scan configuration data
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Validate target_type
    target_type = data.get('target_type')
    if target_type not in ['openapi', 'pcap', 'url']:
        return False, f"Invalid target_type: {target_type}. Must be one of: openapi, pcap, url"
    
    # Validate scan_type
    scan_type = data.get('scan_type', 'full')
    if scan_type not in ['full', 'quick', 'custom']:
        return False, f"Invalid scan_type: {scan_type}. Must be one of: full, quick, custom"
    
    # Validate timeout (must be between 1 and 3600 seconds)
    timeout = data.get('timeout', 300)
    try:
        timeout = int(timeout)
        if timeout < 1 or timeout > 3600:
            return False, f"Invalid timeout: {timeout}. Must be between 1 and 3600 seconds"
    except (ValueError, TypeError):
        return False, f"Invalid timeout value: {timeout}. Must be an integer"
    
    # Validate max_threads (must be between 1 and 16)
    max_threads = data.get('max_threads', 4)
    try:
        max_threads = int(max_threads)
        if max_threads < 1 or max_threads > 16:
            return False, f"Invalid max_threads: {max_threads}. Must be between 1 and 16"
    except (ValueError, TypeError):
        return False, f"Invalid max_threads value: {max_threads}. Must be an integer"
    
    # Validate cognitive_depth (must be between 1 and 5)
    cognitive_depth = data.get('cognitive_depth', 3)
    try:
        cognitive_depth = int(cognitive_depth)
        if cognitive_depth < 1 or cognitive_depth > 5:
            return False, f"Invalid cognitive_depth: {cognitive_depth}. Must be between 1 and 5"
    except (ValueError, TypeError):
        return False, f"Invalid cognitive_depth value: {cognitive_depth}. Must be an integer"
    
    # Validate boolean parameters
    for param in ['enable_fuzzing', 'enable_verification']:
        value = data.get(param)
        if value is not None and not isinstance(value, bool):
            return False, f"Invalid {param}: {value}. Must be a boolean"
    
    # Validate URL format if target_type is url
    if target_type == 'url':
        target = data.get('target')
        if target:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(target)
                if not all([parsed.scheme, parsed.netloc]):
                    return False, f"Invalid URL format: {target}"
                if parsed.scheme not in ['http', 'https']:
                    return False, f"Invalid URL scheme: {parsed.scheme}. Must be http or https"
            except Exception as e:
                return False, f"Invalid URL: {str(e)}"
    
    return True, ""


def initialize_scanner():
    """Initialize the scanner and state manager."""
    global scanner, state_manager
    
    if scanner is None:
        scanner_config = {
            'max_threads': 4,
            'cognitive_depth': 3
        }
        scanner = ScannerManager(config=scanner_config)
        
        state_manager = TargetStateManager(config=scanner_config)
        state_manager.initialize()
        scanner.set_state_manager(state_manager)
        
        # Register phase callbacks for real-time updates
        for phase in ScanPhase:
            scanner.register_phase_callback(phase, phase_update_callback)
        
        logger.info("Scanner initialized")


def phase_update_callback(phase: ScanPhase, scan_result):
    """Callback for scan phase updates - sends WebSocket updates."""
    try:
        socketio.emit('scan_progress', {
            'phase': phase.value,
            'status': scan_result.status.value,
            'endpoints_tested': scan_result.endpoints_tested,
            'payloads_generated': scan_result.payloads_generated,
            'vulnerabilities_found': len(scan_result.vulnerabilities_found),
            'errors': scan_result.errors,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error sending progress update: {e}")


@app.route('/')
def index():
    """Serve the main GUI page."""
    return send_from_directory('static', 'index.html')


@app.route('/api/health', methods=['GET'])
@require_auth
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'scanner_initialized': scanner is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/scan/start', methods=['POST'])
@require_auth
@rate_limit
def start_scan():
    """Start a new scan."""
    global current_scan_id, scan_results
    
    try:
        # Check concurrent scan limit
        can_start, error_msg = can_start_scan()
        if not can_start:
            return jsonify({'error': error_msg}), 429
        
        initialize_scanner()
        
        data = request.get_json()
        target_type = data.get('target_type')  # openapi, pcap, url
        target = data.get('target')
        scan_type = data.get('scan_type', 'full')
        timeout = data.get('timeout', 300)
        max_threads = data.get('max_threads', 4)
        cognitive_depth = data.get('cognitive_depth', 3)
        enable_fuzzing = data.get('enable_fuzzing', False)  # Default to False for security
        enable_verification = data.get('enable_verification', True)
        
        # Validate inputs
        if not target_type or not target:
            return jsonify({'error': 'target_type and target are required'}), 400
        
        # Validate scan configuration parameters
        is_valid, error_msg = validate_scan_config(data)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Validate and sanitize additional_params to prevent injection
        allowed_additional_params = ['target_type', 'url']
        additional_params = {}
        for key, value in data.items():
            if key in allowed_additional_params:
                additional_params[key] = value
            elif key not in ['target_type', 'target', 'scan_type', 'timeout', 'max_threads', 
                            'cognitive_depth', 'enable_fuzzing', 'enable_verification']:
                logger.warning(f"Ignoring unexpected parameter: {key}")
        
        # Ensure target_type is in additional_params
        additional_params['target_type'] = target_type
        if target_type == 'url':
            additional_params['url'] = target
        
        # Validate file exists for openapi and pcap with path traversal protection
        if target_type in ['openapi', 'pcap']:
            is_valid, error_msg = validate_file_path(target)
            if not is_valid:
                return jsonify({'error': error_msg}), 400
        
        # Create scan configuration
        config = ScanConfig(
            target=target,
            scan_type=scan_type,
            max_threads=max_threads,
            timeout=timeout,
            enable_fuzzing=enable_fuzzing,
            enable_verification=enable_verification,
            cognitive_depth=cognitive_depth,
            additional_params=additional_params
        )
        
        # Generate scan ID
        current_scan_id = str(uuid.uuid4())
        scan_results[current_scan_id] = {
            'scan_id': current_scan_id,
            'target': target,
            'target_type': target_type,
            'status': 'starting',
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'config': {
                'scan_type': scan_type,
                'timeout': timeout,
                'max_threads': max_threads,
                'cognitive_depth': cognitive_depth,
                'enable_fuzzing': enable_fuzzing,
                'enable_verification': enable_verification
            }
        }
        
        # Run scan in background thread
        def run_scan_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(scanner.execute_scan(config))
                scan_results[current_scan_id]['status'] = 'completed'
                scan_results[current_scan_id]['end_time'] = datetime.now().isoformat()
                scan_results[current_scan_id]['result'] = {
                    'phase': result.phase.value,
                    'status': result.status.value,
                    'endpoints_tested': result.endpoints_tested,
                    'payloads_generated': result.payloads_generated,
                    'vulnerabilities': result.vulnerabilities_found,
                    'errors': result.errors,
                    'metadata': result.metadata
                }
                socketio.emit('scan_complete', {'scan_id': current_scan_id})
            except Exception as e:
                logger.error(f"Scan error: {e}")
                scan_results[current_scan_id]['status'] = 'failed'
                scan_results[current_scan_id]['error'] = str(e)
                scan_results[current_scan_id]['end_time'] = datetime.now().isoformat()
                socketio.emit('scan_error', {'scan_id': current_scan_id, 'error': str(e)})
            finally:
                loop.close()
                decrement_active_scans()
        
        scan_thread = threading.Thread(target=run_scan_async, daemon=True)
        scan_thread.start()
        
        return jsonify({
            'scan_id': current_scan_id,
            'status': 'started',
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/stop', methods=['POST'])
@require_auth
@rate_limit
def stop_scan():
    """Stop the current scan."""
    try:
        if scanner:
            scanner.stop_scan()
            return jsonify({'status': 'stopping', 'message': 'Scan stop requested'})
        return jsonify({'error': 'No active scan'}), 400
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/status', methods=['GET'])
@require_auth
@rate_limit
def get_scan_status():
    """Get the status of the current or specified scan."""
    scan_id = request.args.get('scan_id', current_scan_id)
    
    if not scan_id or scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])


@app.route('/api/scan/results', methods=['GET'])
@require_auth
@rate_limit
def get_scan_results():
    """Get detailed results for a scan."""
    scan_id = request.args.get('scan_id')
    
    if not scan_id or scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = scan_results[scan_id]
    if 'result' not in scan_data:
        return jsonify({'error': 'Scan not completed yet'}), 400
    
    return jsonify(scan_data['result'])


@app.route('/api/scan/history', methods=['GET'])
@require_auth
@rate_limit
def get_scan_history():
    """Get history of all scans."""
    return jsonify({
        'scans': list(scan_results.values()),
        'total': len(scan_results)
    })


@app.route('/api/scan/<scan_id>/report', methods=['GET'])
@require_auth
@rate_limit
def get_scan_report(scan_id):
    """Get the report for a specific scan."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = scan_results[scan_id]
    if 'result' not in scan_data or 'metadata' not in scan_data['result']:
        return jsonify({'error': 'Report not available'}), 400
    
    report_data = scan_data['result']['metadata'].get('report')
    if report_data:
        return jsonify(json.loads(report_data))
    
    return jsonify({'error': 'Report not generated'}), 400


@app.route('/api/scan/<scan_id>/export', methods=['GET'])
@require_auth
@rate_limit
def export_scan_report(scan_id):
    """Export scan report in specified format."""
    format_type = request.args.get('format', 'json')
    
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = scan_results[scan_id]
    if 'result' not in scan_data:
        return jsonify({'error': 'Scan not completed'}), 400
    
    try:
        from python_brain.reporting.report_generator import ReportGenerator, ScanSummary, VulnerabilityFinding
        
        report_gen = ReportGenerator()
        
        # Reconstruct scan summary and findings
        result = scan_data['result']
        scan_summary = ScanSummary(
            scan_id=scan_id,
            target=scan_data['target'],
            start_time=datetime.fromisoformat(scan_data['start_time']),
            end_time=datetime.fromisoformat(scan_data['end_time']) if scan_data['end_time'] else datetime.now(),
            duration_seconds=0,
            total_endpoints_tested=result.get('endpoints_tested', 0),
            total_payloads_generated=result.get('payloads_generated', 0),
            vulnerabilities_found=len(result.get('vulnerabilities', [])),
            scan_config=scan_data.get('config', {})
        )
        
        findings = []
        for vuln in result.get('vulnerabilities', []):
            finding = report_gen.create_vulnerability_finding(vuln)
            findings.append(finding)
        
        if format_type == 'json':
            content = report_gen.generate_json_report(scan_summary, findings)
            return jsonify(json.loads(content))
        elif format_type == 'html':
            content = report_gen.generate_html_report(scan_summary, findings)
            return content, 200, {'Content-Type': 'text/html'}
        elif format_type == 'markdown':
            content = report_gen.generate_markdown_report(scan_summary, findings)
            return content, 200, {'Content-Type': 'text/markdown'}
        else:
            return jsonify({'error': f'Unsupported format: {format_type}'}), 400
            
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/target/validate', methods=['POST'])
@require_auth
@rate_limit
def validate_target():
    """Validate a target before scanning."""
    try:
        data = request.get_json()
        target_type = data.get('target_type')
        target = data.get('target')
        
        if not target_type or not target:
            return jsonify({'error': 'target_type and target are required'}), 400
        
        validation_result = {'valid': True, 'warnings': []}
        
        if target_type == 'openapi':
            # Validate file path to prevent path traversal
            is_valid, error_msg = validate_file_path(target)
            if not is_valid:
                validation_result['valid'] = False
                validation_result['error'] = error_msg
                return jsonify(validation_result)
            
            parser = OpenAPIParser()
            try:
                spec = parser.parse_file(target)
                validation_result['spec_info'] = {
                    'title': spec.title,
                    'version': spec.version,
                    'endpoints_count': len(spec.endpoints),
                    'base_url': spec.base_url
                }
                if len(spec.endpoints) == 0:
                    validation_result['warnings'].append('No endpoints found in specification')
            except Exception as e:
                validation_result['valid'] = False
                validation_result['error'] = str(e)
                
        elif target_type == 'pcap':
            # Validate file path to prevent path traversal
            is_valid, error_msg = validate_file_path(target)
            if not is_valid:
                validation_result['valid'] = False
                validation_result['error'] = error_msg
                return jsonify(validation_result)
            
            ingestor = PcapIngestor()
            try:
                analysis = ingestor.ingest_file(target)
                validation_result['pcap_info'] = {
                    'total_packets': analysis.total_packets,
                    'unique_ip_port_pairs': len(analysis.unique_ip_port_pairs),
                    'network_flows': len(analysis.network_flows)
                }
                if analysis.total_packets == 0:
                    validation_result['warnings'].append('No packets found in PCAP file')
            except Exception as e:
                validation_result['valid'] = False
                validation_result['error'] = str(e)
                
        elif target_type == 'url':
            # Basic URL validation
            from urllib.parse import urlparse
            try:
                parsed = urlparse(target)
                if not all([parsed.scheme, parsed.netloc]):
                    validation_result['valid'] = False
                    validation_result['error'] = 'Invalid URL format'
                else:
                    validation_result['url_info'] = {
                        'scheme': parsed.scheme,
                        'netloc': parsed.netloc,
                        'path': parsed.path
                    }
            except Exception as e:
                validation_result['valid'] = False
                validation_result['error'] = str(e)
        
        return jsonify(validation_result)
        
    except Exception as e:
        logger.error(f"Error validating target: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['GET', 'POST'])
@require_auth
def handle_config():
    """Get or update scanner configuration."""
    if request.method == 'GET':
        return jsonify({
            'max_threads': 4,
            'cognitive_depth': 3,
            'default_timeout': 300,
            'supported_target_types': ['openapi', 'pcap', 'url'],
            'supported_scan_types': ['full', 'quick', 'custom'],
            'supported_formats': ['json', 'html', 'markdown']
        })
    else:
        # Update configuration (placeholder for future implementation)
        return jsonify({'status': 'config_updated'})


@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    logger.info('Client connected')
    emit('connected', {'message': 'Connected to AEGIS Scanner'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    logger.info('Client disconnected')


def run_server(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask server."""
    logger.info(f"Starting API server on {host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    run_server(debug=True)
