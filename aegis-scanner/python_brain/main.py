"""
AEGIS Security Scanner - CLI Entry Point

This module provides the command-line interface for the AEGIS security scanner.
It parses target specifications (OpenAPI, URL, PCAP), initializes the scanner
manager, and executes scanning phases asynchronously.
"""

import argparse
import asyncio
import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from python_brain.orchestrator.scanner_manager import (
    ScannerManager,
    ScanConfig,
    ScanPhase,
    ScannerStatus
)
from python_brain.orchestrator.target_state import TargetStateManager
from python_brain.ingestion.openapi_parser import OpenAPIParser
from python_brain.ingestion.pcap_ingestor import PcapIngestor
from python_brain.ingestion.topology_mapper import TopologyMapper


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """
    Configure logging for the application.
    
    Args:
        verbose: Enable verbose (DEBUG) logging
        log_file: Optional file to write logs to
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers
    )


def create_parser() -> argparse.ArgumentParser:
    """
    Create the argument parser for the CLI.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description='AEGIS Security Scanner - Advanced security scanning with cognitive analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan an OpenAPI specification
  python -m python_brain.main --target openapi --spec api.yaml
  
  # Scan a URL directly
  python -m python_brain.main --target url --url https://api.example.com
  
  # Analyze a PCAP file
  python -m python_brain.main --target pcap --file capture.pcap
  
  # Quick scan with custom timeout
  python -m python_brain.main --target openapi --spec api.yaml --scan-type quick --timeout 60
        """
    )
    
    # Target specification
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument(
        '--target',
        choices=['openapi', 'url', 'pcap'],
        required=True,
        help='Type of target to scan'
    )
    target_group.add_argument(
        '--spec',
        type=str,
        help='Path to OpenAPI/Swagger specification file (JSON or YAML)'
    )
    target_group.add_argument(
        '--url',
        type=str,
        help='Target URL for direct scanning'
    )
    target_group.add_argument(
        '--file',
        type=str,
        help='Path to PCAP file for network analysis'
    )
    
    # Scan configuration
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument(
        '--scan-type',
        choices=['full', 'quick', 'custom'],
        default='full',
        help='Type of scan to perform (default: full)'
    )
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Scan timeout in seconds (default: 300)'
    )
    scan_group.add_argument(
        '--max-threads',
        type=int,
        default=4,
        help='Maximum number of threads for parallel operations (default: 4)'
    )
    scan_group.add_argument(
        '--cognitive-depth',
        type=int,
        default=3,
        help='Depth of cognitive analysis (1-5, default: 3)'
    )
    
    # Feature toggles
    feature_group = parser.add_argument_group('Feature Toggles')
    feature_group.add_argument(
        '--enable-fuzzing',
        action='store_true',
        default=True,
        help='Enable fuzzing phase (default: True)'
    )
    feature_group.add_argument(
        '--disable-fuzzing',
        action='store_false',
        dest='enable_fuzzing',
        help='Disable fuzzing phase'
    )
    feature_group.add_argument(
        '--enable-verification',
        action='store_true',
        default=True,
        help='Enable verification phase (default: True)'
    )
    feature_group.add_argument(
        '--disable-verification',
        action='store_false',
        dest='enable_verification',
        help='Disable verification phase'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output',
        type=str,
        help='Output file path for scan results (JSON format)'
    )
    output_group.add_argument(
        '--format',
        choices=['json', 'text', 'html'],
        default='json',
        help='Output format (default: json)'
    )
    
    # Logging options
    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose (DEBUG) logging'
    )
    log_group.add_argument(
        '--log-file',
        type=str,
        help='Write logs to specified file'
    )
    
    return parser


def validate_args(args: argparse.Namespace) -> bool:
    """
    Validate command-line arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        True if valid, False otherwise
    """
    if args.target == 'openapi' and not args.spec:
        print("Error: --spec is required for OpenAPI target")
        return False
    
    if args.target == 'url' and not args.url:
        print("Error: --url is required for URL target")
        return False
    
    if args.target == 'pcap' and not args.file:
        print("Error: --file is required for PCAP target")
        return False
    
    if args.cognitive_depth < 1 or args.cognitive_depth > 5:
        print("Error: --cognitive-depth must be between 1 and 5")
        return False
    
    if args.timeout <= 0:
        print("Error: --timeout must be positive")
        return False
    
    if args.max_threads < 1:
        print("Error: --max-threads must be at least 1")
        return False
    
    # Validate file paths exist
    if args.target == 'openapi' and args.spec:
        if not Path(args.spec).exists():
            print(f"Error: OpenAPI spec file not found: {args.spec}")
            return False
    
    if args.target == 'pcap' and args.file:
        if not Path(args.file).exists():
            print(f"Error: PCAP file not found: {args.file}")
            return False
    
    return True


def create_scan_config(args: argparse.Namespace) -> ScanConfig:
    """
    Create ScanConfig from command-line arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        ScanConfig object
    """
    # Determine target string based on target type
    if args.target == 'openapi':
        target = args.spec
    elif args.target == 'url':
        target = args.url
    else:  # pcap
        target = args.file
    
    return ScanConfig(
        target=target,
        scan_type=args.scan_type,
        max_threads=args.max_threads,
        timeout=args.timeout,
        enable_fuzzing=args.enable_fuzzing,
        enable_verification=args.enable_verification,
        cognitive_depth=args.cognitive_depth,
        additional_params={
            'target_type': args.target,
            'url': args.url if args.target == 'url' else None,
            'output_format': args.format
        }
    )


def phase_callback(phase: ScanPhase, scan_result):
    """
    Callback function for scan phase changes.
    
    Args:
        phase: Current scan phase
        scan_result: Current scan result object
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Phase: {phase.value.upper()}")
    
    if phase == ScanPhase.INGESTION:
        logger.info("Ingesting target data...")
    elif phase == ScanPhase.ANALYSIS:
        logger.info("Analyzing targets with cognitive engine...")
    elif phase == ScanPhase.FUZZING:
        logger.info("Executing fuzzing phase...")
    elif phase == ScanPhase.VERIFICATION:
        logger.info("Verifying findings...")
    elif phase == ScanPhase.REPORTING:
        logger.info("Generating report...")
    elif phase == ScanPhase.COMPLETED:
        duration = (scan_result.end_time - scan_result.start_time).total_seconds()
        logger.info(f"Scan completed in {duration:.2f} seconds")
        logger.info(f"Vulnerabilities found: {len(scan_result.vulnerabilities_found)}")
        logger.info(f"Endpoints tested: {scan_result.endpoints_tested}")
    elif phase == ScanPhase.FAILED:
        logger.error("Scan failed!")


async def ingest_target(args: argparse.Namespace, config: ScanConfig) -> Dict[str, Any]:
    """
    Ingest target data based on target type.
    
    Args:
        args: Command-line arguments
        config: Scan configuration
        
    Returns:
        Dictionary containing ingested data
    """
    logger = logging.getLogger(__name__)
    
    if args.target == 'openapi':
        logger.info(f"Parsing OpenAPI specification: {args.spec}")
        parser = OpenAPIParser()
        spec = parser.parse_file(args.spec)
        
        return {
            'type': 'openapi',
            'spec': spec,
            'endpoints_count': len(spec.endpoints)
        }
    
    elif args.target == 'pcap':
        logger.info(f"Ingesting PCAP file: {args.file}")
        ingestor = PcapIngestor()
        analysis = ingestor.ingest_file(args.file)
        
        return {
            'type': 'pcap',
            'analysis': analysis,
            'packets': analysis.total_packets,
            'flows': len(analysis.network_flows)
        }
    
    elif args.target == 'url':
        logger.info(f"Preparing URL scan: {args.url}")
        # For URL scanning, we'd typically discover endpoints first
        # This is a placeholder for future implementation
        return {
            'type': 'url',
            'url': args.url,
            'endpoints_count': 0
        }
    
    return {}


def save_results(scan_result, output_path: str, output_format: str):
    """
    Save scan results to file.
    
    Args:
        scan_result: ScanResult object
        output_path: Path to save results
        output_format: Output format (json, text, html)
    """
    logger = logging.getLogger(__name__)
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    if output_format == 'json':
        import json
        
        result_dict = {
            'phase': scan_result.phase.value,
            'status': scan_result.status.value,
            'start_time': scan_result.start_time.isoformat(),
            'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
            'vulnerabilities_found': scan_result.vulnerabilities_found,
            'endpoints_tested': scan_result.endpoints_tested,
            'payloads_generated': scan_result.payloads_generated,
            'errors': scan_result.errors,
            'metadata': scan_result.metadata
        }
        
        with open(output_file, 'w') as f:
            json.dump(result_dict, f, indent=2)
    
    elif output_format == 'text':
        with open(output_file, 'w') as f:
            f.write(f"AEGIS Security Scan Report\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"Status: {scan_result.status.value}\n")
            f.write(f"Phase: {scan_result.phase.value}\n")
            f.write(f"Start Time: {scan_result.start_time}\n")
            f.write(f"End Time: {scan_result.end_time}\n\n")
            f.write(f"Endpoints Tested: {scan_result.endpoints_tested}\n")
            f.write(f"Payloads Generated: {scan_result.payloads_generated}\n")
            f.write(f"Vulnerabilities Found: {len(scan_result.vulnerabilities_found)}\n\n")
            
            if scan_result.vulnerabilities_found:
                f.write("Vulnerabilities:\n")
                for vuln in scan_result.vulnerabilities_found:
                    f.write(f"  - {vuln}\n")
            
            if scan_result.errors:
                f.write("\nErrors:\n")
                for error in scan_result.errors:
                    f.write(f"  - {error}\n")
    
    elif output_format == 'html':
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AEGIS Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .status {{ padding: 10px; background: #f0f0f0; }}
        .vulnerability {{ padding: 10px; margin: 10px 0; background: #ffcccc; }}
        .error {{ padding: 10px; margin: 10px 0; background: #ffffcc; }}
    </style>
</head>
<body>
    <h1>AEGIS Security Scan Report</h1>
    <div class="status">
        <p><strong>Status:</strong> {scan_result.status.value}</p>
        <p><strong>Phase:</strong> {scan_result.phase.value}</p>
        <p><strong>Start Time:</strong> {scan_result.start_time}</p>
        <p><strong>End Time:</strong> {scan_result.end_time}</p>
        <p><strong>Endpoints Tested:</strong> {scan_result.endpoints_tested}</p>
        <p><strong>Payloads Generated:</strong> {scan_result.payloads_generated}</p>
        <p><strong>Vulnerabilities Found:</strong> {len(scan_result.vulnerabilities_found)}</p>
    </div>
    
    <h2>Vulnerabilities</h2>
    {"".join(f'<div class="vulnerability">{vuln}</div>' for vuln in scan_result.vulnerabilities_found)}
    
    <h2>Errors</h2>
    {"".join(f'<div class="error">{error}</div>' for error in scan_result.errors)}
</body>
</html>
        """
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    logger.info(f"Results saved to: {output_file}")


async def main_async(args: argparse.Namespace):
    """
    Main async function that orchestrates the scanning process.
    
    Args:
        args: Parsed command-line arguments
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Validate arguments
        if not validate_args(args):
            sys.exit(1)
        
        # Create scan configuration
        config = create_scan_config(args)
        logger.info(f"Starting AEGIS security scan")
        logger.info(f"Target: {args.target} - {config.target}")
        logger.info(f"Scan type: {config.scan_type}")
        logger.info(f"Timeout: {config.timeout}s")
        
        # Ingest target data
        ingestion_data = await ingest_target(args, config)
        logger.info(f"Ingestion complete: {ingestion_data}")
        
        # Initialize scanner manager
        scanner_config = {
            'max_threads': config.max_threads,
            'cognitive_depth': config.cognitive_depth
        }
        scanner = ScannerManager(config=scanner_config)
        
        # Register phase callback for progress updates
        scanner.register_phase_callback(ScanPhase.INGESTION, phase_callback)
        scanner.register_phase_callback(ScanPhase.ANALYSIS, phase_callback)
        scanner.register_phase_callback(ScanPhase.FUZZING, phase_callback)
        scanner.register_phase_callback(ScanPhase.VERIFICATION, phase_callback)
        scanner.register_phase_callback(ScanPhase.REPORTING, phase_callback)
        scanner.register_phase_callback(ScanPhase.COMPLETED, phase_callback)
        scanner.register_phase_callback(ScanPhase.FAILED, phase_callback)
        
        # Initialize state manager
        state_manager = TargetStateManager(config=scanner_config)
        state_manager.initialize()
        scanner.set_state_manager(state_manager)
        
        # Register target if we have a base URL
        if args.target == 'openapi':
            openapi_parser = OpenAPIParser()
            spec = openapi_parser.parse_file(args.spec)
            base_url = spec.base_url or args.spec
            state_manager.register_target(
                target=config.target,
                base_url=base_url
            )
        elif args.target == 'url':
            state_manager.register_target(
                target=config.target,
                base_url=args.url
            )
        
        # Execute scan
        logger.info("Executing scan...")
        scan_result = await scanner.execute_scan(config)
        
        # Display results
        print("\n" + "=" * 50)
        print("SCAN RESULTS")
        print("=" * 50)
        print(f"Status: {scan_result.status.value}")
        print(f"Phase: {scan_result.phase.value}")
        print(f"Duration: {(scan_result.end_time - scan_result.start_time).total_seconds():.2f}s")
        print(f"Endpoints tested: {scan_result.endpoints_tested}")
        print(f"Payloads generated: {scan_result.payloads_generated}")
        print(f"Vulnerabilities found: {len(scan_result.vulnerabilities_found)}")
        
        if scan_result.vulnerabilities_found:
            print("\nVulnerabilities:")
            for vuln in scan_result.vulnerabilities_found:
                print(f"  - {vuln}")
        
        if scan_result.errors:
            print("\nErrors:")
            for error in scan_result.errors:
                print(f"  - {error}")
        
        # Save results if output path specified
        if args.output:
            save_results(scan_result, args.output, args.format)
        
        # Clean up
        scanner.stop_event_loop()
        
        # Exit with appropriate code
        if scan_result.status == ScannerStatus.ERROR:
            sys.exit(1)
        elif scan_result.phase == ScanPhase.FAILED:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


def main():
    """
    Main entry point for the CLI.
    """
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.log_file)
    
    # Run async main
    asyncio.run(main_async(args))


if __name__ == '__main__':
    main()
