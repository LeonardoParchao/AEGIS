"""
Scapy integration for rapid Layer 2-3 protocol fuzzing.

This module provides capabilities for generating malformed TCP handshakes,
IPv6 extension headers, and other network protocol anomalies for security testing.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
import random
import struct


class ProtocolLayer(Enum):
    """Network protocol layers for fuzzing."""
    ETHERNET = "ethernet"
    IP = "ip"
    IPV6 = "ipv6"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ARP = "arp"


class FuzzingStrategy(Enum):
    """Fuzzing strategies for protocol manipulation."""
    RANDOM = "random"
    BOUNDARY = "boundary"
    SEQUENTIAL = "sequential"
    STRUCTURAL = "structural"
    SMART = "smart"


@dataclass
class PacketTemplate:
    """Template for packet generation."""
    protocol_layer: ProtocolLayer
    base_packet: Dict[str, Any]
    mutable_fields: List[str]
    constraints: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)


@dataclass
class FuzzedPacket:
    """Represents a fuzzed packet ready for transmission."""
    raw_bytes: bytes
    protocol_layer: ProtocolLayer
    metadata: Dict[str, Any] = field(default_factory=dict)
    mutation_info: Dict[str, Any] = field(default_factory=dict)


class ScapyFuzzer:
    """
    Scapy-based network protocol fuzzer for Layer 2-3 fuzzing.
    
    Generates malformed TCP handshakes, IPv6 extension headers, and other
    protocol anomalies for security testing purposes.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Scapy fuzzer.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.templates: Dict[ProtocolLayer, PacketTemplate] = {}
        self.fuzzing_strategy = FuzzingStrategy(
            self.config.get('strategy', 'random')
        )
        self.mutation_rate = self.config.get('mutation_rate', 0.1)
        self.max_packet_size = self.config.get('max_packet_size', 1500)
        
        # Initialize default templates
        self._initialize_default_templates()
    
    def _initialize_default_templates(self):
        """Initialize default packet templates for common protocols."""
        # TCP template
        self.templates[ProtocolLayer.TCP] = PacketTemplate(
            protocol_layer=ProtocolLayer.TCP,
            base_packet={
                'src_port': 12345,
                'dst_port': 80,
                'seq': 1000,
                'ack': 0,
                'flags': 'S',
                'window': 8192,
                'urgent': 0,
            },
            mutable_fields=['src_port', 'dst_port', 'seq', 'ack', 'flags', 'window'],
            constraints={
                'src_port': (1, 65535),
                'dst_port': (1, 65535),
                'window': (0, 65535),
            }
        )
        
        # IPv6 template
        self.templates[ProtocolLayer.IPV6] = PacketTemplate(
            protocol_layer=ProtocolLayer.IPV6,
            base_packet={
                'version': 6,
                'traffic_class': 0,
                'flow_label': 0,
                'payload_length': 0,
                'next_header': 6,  # TCP
                'hop_limit': 64,
            },
            mutable_fields=['traffic_class', 'flow_label', 'hop_limit'],
            constraints={
                'traffic_class': (0, 255),
                'flow_label': (0, 1048575),
                'hop_limit': (0, 255),
            }
        )
        
        # UDP template
        self.templates[ProtocolLayer.UDP] = PacketTemplate(
            protocol_layer=ProtocolLayer.UDP,
            base_packet={
                'src_port': 12345,
                'dst_port': 53,
                'length': 0,
                'checksum': 0,
            },
            mutable_fields=['src_port', 'dst_port', 'length'],
            constraints={
                'src_port': (1, 65535),
                'dst_port': (1, 65535),
            }
        )
    
    def generate_malformed_tcp_handshake(
        self,
        target_port: int,
        mutations: int = 10
    ) -> List[FuzzedPacket]:
        """
        Generate malformed TCP handshake packets.
        
        Args:
            target_port: Target port for the handshake
            mutations: Number of mutations to generate
            
        Returns:
            List of fuzzed TCP packets
        """
        template = self.templates[ProtocolLayer.TCP]
        packets = []
        
        for i in range(mutations):
            packet_data = template.base_packet.copy()
            packet_data['dst_port'] = target_port
            
            # Apply mutations based on strategy
            mutated = self._apply_mutations(template, packet_data)
            
            # Add specific TCP handshake anomalies
            anomaly_type = random.choice([
                'invalid_flags',
                'sequence_anomaly',
                'window_overflow',
                'urgent_pointer',
                'checksum_invalid'
            ])
            
            self._apply_tcp_anomaly(mutated, anomaly_type)
            
            raw_bytes = self._build_tcp_packet(mutated)
            
            packets.append(FuzzedPacket(
                raw_bytes=raw_bytes,
                protocol_layer=ProtocolLayer.TCP,
                metadata={
                    'anomaly_type': anomaly_type,
                    'target_port': target_port,
                },
                mutation_info=mutated
            ))
        
        return packets
    
    def generate_ipv6_extension_headers(
        self,
        mutations: int = 10
    ) -> List[FuzzedPacket]:
        """
        Generate malformed IPv6 extension headers.
        
        Args:
            mutations: Number of mutations to generate
            
        Returns:
            List of fuzzed IPv6 packets
        """
        template = self.templates[ProtocolLayer.IPV6]
        packets = []
        
        extension_types = [
            0,   # Hop-by-Hop Options
            43,  # Routing
            44,  # Fragment
            50,  # Encapsulating Security Payload
            51,  # Authentication Header
            60,  # Destination Options
        ]
        
        for i in range(mutations):
            packet_data = template.base_packet.copy()
            
            # Apply mutations
            mutated = self._apply_mutations(template, packet_data)
            
            # Add extension header anomalies
            ext_type = random.choice(extension_types)
            anomaly_type = random.choice([
                'invalid_length',
                'circular_extension',
                'overflow_chain',
                'malformed_options',
                'zero_length'
            ])
            
            self._apply_ipv6_anomaly(mutated, ext_type, anomaly_type)
            
            raw_bytes = self._build_ipv6_packet(mutated)
            
            packets.append(FuzzedPacket(
                raw_bytes=raw_bytes,
                protocol_layer=ProtocolLayer.IPV6,
                metadata={
                    'anomaly_type': anomaly_type,
                    'extension_type': ext_type,
                },
                mutation_info=mutated
            ))
        
        return packets
    
    def generate_udp_flood(
        self,
        target_port: int,
        packet_count: int = 100
    ) -> List[FuzzedPacket]:
        """
        Generate UDP flood packets.
        
        Args:
            target_port: Target port for UDP packets
            packet_count: Number of packets to generate
            
        Returns:
            List of fuzzed UDP packets
        """
        template = self.templates[ProtocolLayer.UDP]
        packets = []
        
        for i in range(packet_count):
            packet_data = template.base_packet.copy()
            packet_data['dst_port'] = target_port
            
            # Apply random mutations
            mutated = self._apply_mutations(template, packet_data)
            
            # Add UDP-specific anomalies
            anomaly_type = random.choice([
                'length_mismatch',
                'checksum_zero',
                'overflow_length',
                'invalid_port'
            ])
            
            self._apply_udp_anomaly(mutated, anomaly_type)
            
            raw_bytes = self._build_udp_packet(mutated)
            
            packets.append(FuzzedPacket(
                raw_bytes=raw_bytes,
                protocol_layer=ProtocolLayer.UDP,
                metadata={
                    'anomaly_type': anomaly_type,
                    'target_port': target_port,
                },
                mutation_info=mutated
            ))
        
        return packets
    
    def _apply_mutations(
        self,
        template: PacketTemplate,
        packet_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply mutations based on the configured strategy."""
        mutated = packet_data.copy()
        
        for field in template.mutable_fields:
            if random.random() < self.mutation_rate:
                if field in template.constraints:
                    min_val, max_val = template.constraints[field]
                    mutated[field] = self._mutate_value(
                        mutated[field],
                        min_val,
                        max_val
                    )
                else:
                    mutated[field] = self._mutate_value(mutated[field])
        
        return mutated
    
    def _mutate_value(
        self,
        value: Any,
        min_val: Optional[Any] = None,
        max_val: Optional[Any] = None
    ) -> Any:
        """Mutate a value based on the fuzzing strategy."""
        if self.fuzzing_strategy == FuzzingStrategy.RANDOM:
            if isinstance(value, int):
                if min_val is not None and max_val is not None:
                    return random.randint(min_val, max_val)
                return random.randint(0, value * 2)
            elif isinstance(value, str):
                return self._random_string(len(value))
        
        elif self.fuzzing_strategy == FuzzingStrategy.BOUNDARY:
            if isinstance(value, int):
                boundaries = [0, 1, -1, 255, 256, 65535, 65536, -1]
                if min_val is not None:
                    boundaries.extend([min_val, min_val - 1, min_val + 1])
                if max_val is not None:
                    boundaries.extend([max_val, max_val - 1, max_val + 1])
                return random.choice(boundaries)
        
        elif self.fuzzing_strategy == FuzzingStrategy.SEQUENTIAL:
            if isinstance(value, int):
                return value + 1
        
        return value
    
    def _random_string(self, length: int) -> str:
        """Generate a random string of given length."""
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _apply_tcp_anomaly(self, packet_data: Dict[str, Any], anomaly_type: str):
        """Apply TCP-specific anomalies."""
        if anomaly_type == 'invalid_flags':
            invalid_flags = ['X', 'Y', 'Z', 'INVALID', '']
            packet_data['flags'] = random.choice(invalid_flags)
        
        elif anomaly_type == 'sequence_anomaly':
            packet_data['seq'] = random.randint(-1000000, 1000000)
            packet_data['ack'] = random.randint(-1000000, 1000000)
        
        elif anomaly_type == 'window_overflow':
            packet_data['window'] = random.randint(65536, 999999)
        
        elif anomaly_type == 'urgent_pointer':
            packet_data['urgent'] = random.randint(65536, 999999)
        
        elif anomaly_type == 'checksum_invalid':
            # Will be handled during packet building
            packet_data['checksum_invalid'] = True
    
    def _apply_ipv6_anomaly(
        self,
        packet_data: Dict[str, Any],
        ext_type: int,
        anomaly_type: str
    ):
        """Apply IPv6 extension header anomalies."""
        packet_data['extension_type'] = ext_type
        packet_data['extension_anomaly'] = anomaly_type
        
        if anomaly_type == 'invalid_length':
            packet_data['payload_length'] = random.randint(65536, 999999)
        
        elif anomaly_type == 'circular_extension':
            packet_data['next_header'] = ext_type  # Self-referencing
        
        elif anomaly_type == 'overflow_chain':
            packet_data['extension_chain_length'] = 100  # Excessive chain
        
        elif anomaly_type == 'zero_length':
            packet_data['payload_length'] = 0
        
        elif anomaly_type == 'malformed_options':
            packet_data['malformed_options'] = True
    
    def _apply_udp_anomaly(self, packet_data: Dict[str, Any], anomaly_type: str):
        """Apply UDP-specific anomalies."""
        if anomaly_type == 'length_mismatch':
            packet_data['length'] = random.randint(1, 8)
        
        elif anomaly_type == 'checksum_zero':
            packet_data['checksum'] = 0
        
        elif anomaly_type == 'overflow_length':
            packet_data['length'] = random.randint(65536, 999999)
        
        elif anomaly_type == 'invalid_port':
            packet_data['dst_port'] = random.choice([0, 65536, -1])
    
    def _build_tcp_packet(self, packet_data: Dict[str, Any]) -> bytes:
        """Build raw TCP packet bytes."""
        # TCP header construction (simplified)
        src_port = packet_data.get('src_port', 12345) & 0xFFFF
        dst_port = packet_data.get('dst_port', 80) & 0xFFFF
        seq = packet_data.get('seq', 1000) & 0xFFFFFFFF
        ack = packet_data.get('ack', 0) & 0xFFFFFFFF
        window = packet_data.get('window', 8192) & 0xFFFF
        urgent = packet_data.get('urgent', 0) & 0xFFFF
        
        # Map flags to TCP flags
        flags_map = {
            'S': 0x02,  # SYN
            'A': 0x10,  # ACK
            'F': 0x01,  # FIN
            'R': 0x04,  # RST
            'P': 0x08,  # PSH
            'U': 0x20,  # URG
        }
        flags_str = packet_data.get('flags', 'S')
        flags = 0
        for f in flags_str:
            flags |= flags_map.get(f, 0)
        
        # Build TCP header
        tcp_header = struct.pack(
            '!HHIIBBHHH',
            src_port,
            dst_port,
            seq,
            ack,
            (5 << 4) | 0,  # Data offset (5 * 4 = 20 bytes) + reserved
            flags,
            window,
            0,  # checksum (placeholder)
            urgent
        )
        
        return tcp_header
    
    def _build_ipv6_packet(self, packet_data: Dict[str, Any]) -> bytes:
        """Build raw IPv6 packet bytes."""
        version = packet_data.get('version', 6) & 0x0F
        traffic_class = packet_data.get('traffic_class', 0) & 0xFF
        flow_label = packet_data.get('flow_label', 0) & 0xFFFFF
        payload_length = packet_data.get('payload_length', 0) & 0xFFFF
        next_header = packet_data.get('next_header', 6) & 0xFF
        hop_limit = packet_data.get('hop_limit', 64) & 0xFF
        
        # Build IPv6 header
        ipv6_header = struct.pack(
            '!BBHBBH',
            (version << 4) | ((traffic_class >> 4) & 0x0F),
            ((traffic_class & 0x0F) << 4) | ((flow_label >> 16) & 0x0F),
            flow_label & 0xFFFF,
            payload_length,
            next_header,
            hop_limit
        )
        
        # Add extension header if present
        if 'extension_type' in packet_data:
            ext_header = self._build_extension_header(packet_data)
            return ipv6_header + ext_header
        
        return ipv6_header
    
    def _build_extension_header(self, packet_data: Dict[str, Any]) -> bytes:
        """Build IPv6 extension header."""
        ext_type = packet_data.get('extension_type', 0)
        anomaly = packet_data.get('extension_anomaly', '')
        
        if anomaly == 'invalid_length':
            length = random.randint(256, 1000)
        elif anomaly == 'zero_length':
            length = 0
        else:
            length = random.randint(0, 8)
        
        # Basic extension header format
        ext_header = struct.pack(
            '!BB',
            ext_type,
            length
        )
        
        return ext_header
    
    def _build_udp_packet(self, packet_data: Dict[str, Any]) -> bytes:
        """Build raw UDP packet bytes."""
        src_port = packet_data.get('src_port', 12345) & 0xFFFF
        dst_port = packet_data.get('dst_port', 53) & 0xFFFF
        length = packet_data.get('length', 0) & 0xFFFF
        checksum = packet_data.get('checksum', 0) & 0xFFFF
        
        # Build UDP header
        udp_header = struct.pack(
            '!HHHH',
            src_port,
            dst_port,
            length,
            checksum
        )
        
        return udp_header
    
    def add_custom_template(self, template: PacketTemplate):
        """
        Add a custom packet template.
        
        Args:
            template: PacketTemplate to add
        """
        self.templates[template.protocol_layer] = template
    
    def set_fuzzing_strategy(self, strategy: FuzzingStrategy):
        """
        Set the fuzzing strategy.
        
        Args:
            strategy: FuzzingStrategy to use
        """
        self.fuzzing_strategy = strategy
    
    def set_mutation_rate(self, rate: float):
        """
        Set the mutation rate (0.0 to 1.0).
        
        Args:
            rate: Mutation rate
        """
        self.mutation_rate = max(0.0, min(1.0, rate))
    
    def serialize_packet(self, packet: FuzzedPacket) -> bytes:
        """
        Serialize a fuzzed packet for transmission.
        
        Args:
            packet: FuzzedPacket to serialize
            
        Returns:
            Serialized bytes
        """
        packet_dict = {
            'raw_bytes': packet.raw_bytes.hex(),
            'protocol_layer': packet.protocol_layer.value,
            'metadata': packet.metadata,
            'mutation_info': packet.mutation_info,
        }
        import json
        return json.dumps(packet_dict).encode('utf-8')
    
    def deserialize_packet(self, data: bytes) -> FuzzedPacket:
        """
        Deserialize a packet from bytes.
        
        Args:
            data: Serialized packet bytes
            
        Returns:
            FuzzedPacket object
        """
        import json
        packet_dict = json.loads(data.decode('utf-8'))
        return FuzzedPacket(
            raw_bytes=bytes.fromhex(packet_dict['raw_bytes']),
            protocol_layer=ProtocolLayer(packet_dict['protocol_layer']),
            metadata=packet_dict.get('metadata', {}),
            mutation_info=packet_dict.get('mutation_info', {})
        )
