# Project AEGIS

AEGIS Security Scanner - Advanced security scanning with cognitive analysis, eBPF kernel tracing, and Z3 constraint solving.

## Features

- **Multi-Target Scanning**: Support for OpenAPI specifications, PCAP network captures, and direct URL scanning
- **Cognitive Analysis**: Z3 SMT solver for constraint-based vulnerability detection
- **eBPF Tracing**: Kernel-level execution tracing for verification
- **Fuzzing Engine**: Automated payload generation and testing
- **CVE Matching**: Automatic vulnerability correlation with CVE database
- **Modern Web GUI**: Real-time scan monitoring with React-based interface
- **Multiple Report Formats**: JSON, HTML, and Markdown report generation

## Architecture

AEGIS consists of three main layers:

1. **Python Cognitive Layer**: Orchestrates scanning, performs Z3 constraint solving, and manages state
2. **Rust Userspace Layer**: High-performance I/O operations and network fuzzing (via PyO3 bridge)
3. **eBPF Kernel Layer**: Low-level system call tracing and monitoring (via Aya BPF framework)

### Components

- `python_brain/orchestrator/`: Scan management and coordination
- `python_brain/ingestion/`: Target data ingestion (OpenAPI, PCAP)
- `python_brain/cognitive/`: Z3 SMT solver and payload generation
- `python_brain/reporting/`: Report generation and CVE matching
- `python_brain/verification/`: eBPF-based verification
- `python_brain/gui/`: Web interface with Flask backend and React frontend
- `rust_workspace/aegis_ebpf/`: eBPF programs for kernel tracing
- `rust_workspace/aegis_userspace/`: Rust userspace components

## Installation

### Prerequisites

- Python 3.8 or higher
- Rust toolchain (for eBPF components)
- Linux kernel headers (for eBPF compilation)
- Z3 solver

### Install Python Dependencies

```bash
pip install -e .
```

Or install manually:

```bash
pip install z3-solver scapy pyyaml requests aiohttp flask flask-cors flask-socketio python-socketio eventlet
```

### Build Rust Components

```bash
cd rust_workspace
cargo build --release
```

## Usage

### Command Line Interface

```bash
# Scan an OpenAPI specification
python -m python_brain.main --target openapi --spec api.yaml

# Scan a URL directly
python -m python_brain.main --target url --url https://api.example.com

# Analyze a PCAP file
python -m python_brain.main --target pcap --file capture.pcap

# Quick scan with custom timeout
python -m python_brain.main --target openapi --spec api.yaml --scan-type quick --timeout 60
```

### Web GUI

Launch the graphical interface:

```bash
python start_gui.py
```

Or specify custom host/port:

```bash
python start_gui.py --host 127.0.0.1 --port 8080
```

The GUI will automatically open in your browser at `http://localhost:5000`.

#### GUI Features

- **Scan Configuration**: Easy-to-use forms for target selection and scan parameters
- **Real-time Progress**: Live updates on scan phases, endpoints tested, and vulnerabilities found
- **Results Visualization**: Detailed vulnerability reports with severity ratings and CVSS scores
- **Export Options**: Download reports in JSON, HTML, or Markdown format
- **Scan History**: View and manage past scans

## Configuration

### Scan Parameters

- `--scan-type`: full, quick, or custom
- `--timeout`: Maximum scan duration in seconds (default: 300)
- `--max-threads`: Number of parallel threads (default: 4)
- `--cognitive-depth`: Depth of cognitive analysis (1-5, default: 3)
- `--enable-fuzzing`: Enable/disable fuzzing phase (default: True)
- `--enable-verification`: Enable/disable verification phase (default: True)

### OWASP Rules

AEGIS includes OWASP Top 10 rules for API security and web application security:

- `configs/owasp_api_top10_rules.yaml`: API-specific security rules
- `configs/owasp_top10_rules.yaml`: General web application security rules

## Development

### Running Tests

```bash
pytest tests/
```

### Code Style

```bash
# Format code
black python_brain/

# Lint code
ruff check python_brain/

# Type checking
mypy python_brain/
```

## API Documentation

### REST API Endpoints

- `GET /api/health` - Health check
- `POST /api/scan/start` - Start a new scan
- `POST /api/scan/stop` - Stop current scan
- `GET /api/scan/status` - Get scan status
- `GET /api/scan/results` - Get scan results
- `GET /api/scan/history` - Get scan history
- `GET /api/scan/<id>/report` - Get scan report
- `GET /api/scan/<id>/export` - Export scan report
- `POST /api/target/validate` - Validate target before scanning
- `GET /api/config` - Get/set configuration

### WebSocket Events

- `scan_progress` - Real-time scan progress updates
- `scan_complete` - Scan completion notification
- `scan_error` - Scan error notification

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## Support

For issues and questions, please open an issue on the project repository.
