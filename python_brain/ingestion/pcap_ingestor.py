"""
PCAP ingestor for AEGIS security scanner.

This module ingests PCAP files using scapy to extract unique IP/port pairs
and identify proprietary protocols for the Rust network engine to fuzz.
"""

from typing import Dict, List, Optional, Any, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections import defaultdict
import struct


class Protocol(Enum):
    """Network protocol types."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    UNKNOWN = "unknown"


@dataclass
class IPPortPair:
    """Represents a unique IP and port combination."""
    ip_address: str
    port: int
    protocol: Protocol
    is_server: bool = False  # True if likely a server port
    service: Optional[str] = None  # Identified service name
    confidence: float = 1.0


@dataclass
class NetworkFlow:
    """Represents a bidirectional network flow."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: Protocol
    packet_count: int = 0
    byte_count: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: float = 0.0


@dataclass
class ProtocolSignature:
    """Represents a proprietary protocol signature."""
    name: str
    pattern: bytes
    offset: int = 0
    confidence: float = 1.0
    description: Optional[str] = None


@dataclass
class PcapAnalysis:
    """Results of PCAP analysis."""
    file_path: str
    total_packets: int = 0
    unique_ip_port_pairs: List[IPPortPair] = field(default_factory=list)
    network_flows: List[NetworkFlow] = field(default_factory=list)
    identified_protocols: Dict[str, List[ProtocolSignature]] = field(default_factory=dict)
    proprietary_protocols: List[ProtocolSignature] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PcapIngestor:
    """
    Ingest PCAP files using scapy.
    
    Extracts unique IP/port pairs and identifies proprietary protocols
    for the Rust network engine to fuzz.
    """
    
    # Common server ports
    WELL_KNOWN_PORTS = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        445: 'smb',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        6379: 'redis',
        27017: 'mongodb',
    }
    
    # Common protocol signatures
    PROTOCOL_SIGNATURES = [
        ProtocolSignature("HTTP", b"HTTP/", 0, 0.9, "HTTP protocol"),
        ProtocolSignature("HTTP", b"GET ", 0, 0.9, "HTTP GET request"),
        ProtocolSignature("HTTP", b"POST ", 0, 0.9, "HTTP POST request"),
        ProtocolSignature("SSH", b"SSH-", 0, 0.95, "SSH protocol"),
        ProtocolSignature("FTP", b"220 ", 0, 0.9, "FTP response"),
        ProtocolSignature("SMTP", b"220 ", 0, 0.8, "SMTP greeting"),
        ProtocolSignature("DNS", b"\x00\x00", 0, 0.7, "DNS transaction ID"),
        ProtocolSignature("TLS", b"\x16\x03", 0, 0.95, "TLS handshake"),
        ProtocolSignature("SMB", b"\xff\x53\x4d\x42", 0, 0.95, "SMB header"),
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the PCAP ingestor.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.max_flows = self.config.get('max_flows', 10000)
        self.custom_signatures = self.config.get('protocol_signatures', [])
        
    def ingest_file(self, file_path: Union[str, Path]) -> PcapAnalysis:
        """
        Ingest and analyze a PCAP file.
        
        Args:
            file_path: Path to the PCAP file
            
        Returns:
            PcapAnalysis object containing analysis results
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        
        try:
            from scapy.all import rdpcap, TCP, UDP, ICMP, IP, IPv6, Raw
        except ImportError:
            raise ImportError("scapy is required for PCAP ingestion. Install with: pip install scapy")
        
        packets = rdpcap(str(file_path))
        
        analysis = PcapAnalysis(file_path=str(file_path))
        analysis.total_packets = len(packets)
        
        # Track flows and IP/port pairs
        flows_dict = {}
        ip_port_set = set()
        
        for packet in packets:
            if IP in packet or IPv6 in packet:
                ip_layer = packet[IP] if IP in packet else packet[IPv6]
                
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                protocol = Protocol.UNKNOWN
                src_port = None
                dst_port = None
                
                if TCP in packet:
                    protocol = Protocol.TCP
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = Protocol.UDP
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif ICMP in packet:
                    protocol = Protocol.ICMP
                
                # Track flows
                if src_port and dst_port:
                    flow_key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)
                    if flow_key not in flows_dict:
                        flows_dict[flow_key] = NetworkFlow(
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            protocol=protocol
                        )
                    
                    flow = flows_dict[flow_key]
                    flow.packet_count += 1
                    flow.byte_count += len(packet)
                    
                    if flow.start_time is None:
                        flow.start_time = packet.time
                    flow.end_time = packet.time
                
                # Track unique IP/port pairs
                if src_port:
                    ip_port_set.add((src_ip, src_port, protocol.value))
                if dst_port:
                    ip_port_set.add((dst_ip, dst_port, protocol.value))
                
                # Identify protocols from payload
                if Raw in packet:
                    self._identify_protocols(packet[Raw].load, analysis)
        
        # Convert flows to list
        analysis.network_flows = list(flows_dict.values())
        
        # Calculate flow durations
        for flow in analysis.network_flows:
            if flow.start_time and flow.end_time:
                flow.duration = flow.end_time - flow.start_time
        
        # Convert IP/port pairs to structured objects
        for ip, port, proto_str in ip_port_set:
            protocol = Protocol(proto_str)
            is_server = port in self.WELL_KNOWN_PORTS
            service = self.WELL_KNOWN_PORTS.get(port)
            
            analysis.unique_ip_port_pairs.append(IPPortPair(
                ip_address=ip,
                port=port,
                protocol=protocol,
                is_server=is_server,
                service=service
            ))
        
        # Sort by port and IP for consistency
        analysis.unique_ip_port_pairs.sort(key=lambda x: (x.port, x.ip_address))
        
        return analysis
    
    def _get_flow_key(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: Protocol
    ) -> str:
        """Generate a unique key for a network flow."""
        # Normalize to ensure bidirectional flows have the same key
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol.value}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol.value}"
    
    def _identify_protocols(self, payload: bytes, analysis: PcapAnalysis):
        """Identify protocols from packet payload."""
        all_signatures = self.PROTOCOL_SIGNATURES + self.custom_signatures
        
        for signature in all_signatures:
            if len(payload) > signature.offset + len(signature.pattern):
                if payload[signature.offset:signature.offset + len(signature.pattern)] == signature.pattern:
                    if signature.name not in analysis.identified_protocols:
                        analysis.identified_protocols[signature.name] = []
                    analysis.identified_protocols[signature.name].append(signature)
    
    def identify_proprietary_protocols(
        self,
        analysis: PcapAnalysis,
        threshold: float = 0.5
    ) -> List[ProtocolSignature]:
        """
        Identify potential proprietary protocols from analysis.
        
        Args:
            analysis: PcapAnalysis results
            threshold: Confidence threshold for proprietary protocol detection
            
        Returns:
            List of proprietary protocol signatures
        """
        proprietary = []
        
        # Check for protocols with low confidence or unknown patterns
        for protocol_name, signatures in analysis.identified_protocols.items():
            for sig in signatures:
                if sig.confidence < threshold:
                    proprietary.append(sig)
        
        # If no known protocols are identified in a flow, mark as potentially proprietary
        if not analysis.identified_protocols and analysis.network_flows:
            for flow in analysis.network_flows:
                if flow.protocol in [Protocol.TCP, Protocol.UDP] and flow.packet_count > 10:
                    # Create a signature for the unknown protocol
                    proprietary.append(ProtocolSignature(
                        name=f"unknown_{flow.protocol.value}_{flow.dst_port}",
                        pattern=b"",
                        confidence=0.3,
                        description=f"Unknown protocol on port {flow.dst_port}"
                    ))
        
        analysis.proprietary_protocols = proprietary
        return proprietary
    
    def get_server_ports(self, analysis: PcapAnalysis) -> List[int]:
        """Get all identified server ports."""
        return list(set(pair.port for pair in analysis.unique_ip_port_pairs if pair.is_server))
    
    def get_unique_ips(self, analysis: PcapAnalysis) -> List[str]:
        """Get all unique IP addresses."""
        return list(set(pair.ip_address for pair in analysis.unique_ip_port_pairs))
    
    def get_flows_by_protocol(self, analysis: PcapAnalysis, protocol: Protocol) -> List[NetworkFlow]:
        """Get all flows for a specific protocol."""
        return [flow for flow in analysis.network_flows if flow.protocol == protocol]
    
    def export_for_rust(self, analysis: PcapAnalysis) -> Dict[str, Any]:
        """
        Export analysis results in a format suitable for the Rust network engine.
        
        Returns:
            Dictionary with data structured for Rust consumption
        """
        return {
            'targets': [
                {
                    'ip': pair.ip_address,
                    'port': pair.port,
                    'protocol': pair.protocol.value,
                    'service': pair.service,
                    'is_server': pair.is_server
                }
                for pair in analysis.unique_ip_port_pairs
            ],
            'flows': [
                {
                    'src_ip': flow.src_ip,
                    'src_port': flow.src_port,
                    'dst_ip': flow.dst_ip,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol.value,
                    'packet_count': flow.packet_count,
                    'byte_count': flow.byte_count,
                    'duration': flow.duration
                }
                for flow in analysis.network_flows
            ],
            'proprietary_protocols': [
                {
                    'name': sig.name,
                    'pattern': sig.pattern.hex(),
                    'offset': sig.offset,
                    'confidence': sig.confidence,
                    'description': sig.description
                }
                for sig in analysis.proprietary_protocols
            ],
            'metadata': analysis.metadata
        }
