"""
AEGIS Scanner GUI Startup Script

This script launches the Flask API server and opens the web interface.
"""

import sys
import subprocess
import webbrowser
import time
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = [
        'flask',
        'flask_cors',
        'flask_socketio',
        'socketio',
        'eventlet'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('_', '-'))
        except ImportError:
            missing.append(package)
    
    if missing:
        logger.error(f"Missing required packages: {', '.join(missing)}")
        logger.info("Install with: pip install " + ' '.join(missing))
        return False
    
    return True


def start_gui_server(host='0.0.0.0', port=5000, open_browser=True):
    """
    Start the GUI server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        open_browser: Whether to open browser automatically
    """
    if not check_dependencies():
        sys.exit(1)
    
    logger.info("Starting AEGIS Scanner GUI...")
    logger.info(f"Server will be available at http://{host}:{port}")
    
    # Import the GUI server
    try:
        from python_brain.gui.api_server import run_server
    except ImportError as e:
        logger.error(f"Failed to import GUI server: {e}")
        logger.info("Make sure you're running from the project root directory")
        sys.exit(1)
    
    # Open browser after a short delay
    if open_browser:
        def open_browser_delayed():
            time.sleep(1.5)
            webbrowser.open(f'http://localhost:{port}')
        
        import threading
        browser_thread = threading.Thread(target=open_browser_delayed, daemon=True)
        browser_thread.start()
    
    # Start the server
    try:
        run_server(host=host, port=port, debug=False)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Start the AEGIS Scanner GUI'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to listen on (default: 5000)'
    )
    parser.add_argument(
        '--no-browser',
        action='store_true',
        help='Do not open browser automatically'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Run in debug mode'
    )
    
    args = parser.parse_args()
    
    start_gui_server(
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser
    )
