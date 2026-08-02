"""
Flask API Server for AEGIS Scanner GUI

Provides REST endpoints for the web interface to interact with the scanner.
"""

import asyncio
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import uuid

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

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
app.config['SECRET_KEY'] = 'aegis-scanner-secret-key-change-in-production'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global scanner instance
scanner: Optional[ScannerManager] = None
state_manager: Optional[TargetStateManager] = None
current_scan_id: Optional[str] = None
scan_results: Dict[str, Any] = {}


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
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'scanner_initialized': scanner is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan."""
    global current_scan_id, scan_results
    
    try:
        initialize_scanner()
        
        data = request.get_json()
        target_type = data.get('target_type')  # openapi, pcap, url
        target = data.get('target')
        scan_type = data.get('scan_type', 'full')
        timeout = data.get('timeout', 300)
        max_threads = data.get('max_threads', 4)
        cognitive_depth = data.get('cognitive_depth', 3)
        enable_fuzzing = data.get('enable_fuzzing', True)
        enable_verification = data.get('enable_verification', True)
        
        # Validate inputs
        if not target_type or not target:
            return jsonify({'error': 'target_type and target are required'}), 400
        
        # Validate file exists for openapi and pcap
        if target_type in ['openapi', 'pcap']:
            target_path = Path(target)
            if not target_path.exists():
                return jsonify({'error': f'Target file not found: {target}'}), 400
        
        # Create scan configuration
        config = ScanConfig(
            target=target,
            scan_type=scan_type,
            max_threads=max_threads,
            timeout=timeout,
            enable_fuzzing=enable_fuzzing,
            enable_verification=enable_verification,
            cognitive_depth=cognitive_depth,
            additional_params={
                'target_type': target_type,
                'url': target if target_type == 'url' else None
            }
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
def get_scan_status():
    """Get the status of the current or specified scan."""
    scan_id = request.args.get('scan_id', current_scan_id)
    
    if not scan_id or scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])


@app.route('/api/scan/results', methods=['GET'])
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
def get_scan_history():
    """Get history of all scans."""
    return jsonify({
        'scans': list(scan_results.values()),
        'total': len(scan_results)
    })


@app.route('/api/scan/<scan_id>/report', methods=['GET'])
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
