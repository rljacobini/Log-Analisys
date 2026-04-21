# =============================================================================
# PCAP Reader - Lectura de archivos PCAP
# =============================================================================
#
# Este modulo lee y parsea archivos PCAP (libpcap format) para analisis de
# trafico de red. Soporta los protocolos mas comunes.
#
# Formatos soportados:
#   - PCAP (libpcap)
#   - Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP
#
# Uso:
#   from pcap.pcap_reader import PCAPReader
#
#   reader = PCAPReader("capture.pcap")
#   packets = reader.read_packets()
#   tcp_packets = reader.filter_by_protocol("tcp")
#
# =============================================================================

import struct
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# =============================================================================
# Estructuras de Datos
# =============================================================================

@dataclass
class Packet:
    """Representa un paquete capturando."""
    timestamp: float
    captured_length: int
    original_length: int
    eth_src: str = ""
    eth_dst: str = ""
    eth_type: int = 0
    ip_src: str = ""
    ip_dst: str = ""
    ip_protocol: int = 0
    ip_ttl: int = 64
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_window: int = 0
    udp_length: int = 0
    icmp_type: int = 0
    icmp_code: int = 0
    raw_data: bytes = b""
    protocol: str = "unknown"

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "captured_length": self.captured_length,
            "original_length": self.original_length,
            "eth_src": self.eth_src,
            "eth_dst": self.eth_dst,
            "eth_type": self.eth_type,
            "ip_src": self.ip_src,
            "ip_dst": self.ip_dst,
            "ip_protocol": self.ip_protocol,
            "ip_ttl": self.ip_ttl,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "protocol": self.protocol,
            "raw_data": self.raw_data.hex() if self.raw_data else ""
        }


@dataclass
class Session:
    """Representa una sesion de comunicacion."""
    key: str  # src_ip:src_port -> dst_ip:dst_port
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: List[Packet] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    syn_seen: bool = False
    synack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False


# =============================================================================
# Constantes de Protocolos
# =============================================================================

ETHERNET = 0x0800      # IPv4
ETHERNET_IPV6 = 0x86DD # IPv6
ETHERNET_ARP = 0x0806  # ARP

IPPROTOCOL_ICMP = 1
IPPROTOCOL_TCP = 6
IPPROTOCOL_UDP = 17

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20
TCP_FLAG_ECE = 0x40
TCP_FLAG_CWR = 0x80

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


# =============================================================================
# Clase PCAP Reader
# =============================================================================

class PCAPReader:
    """Lectura de archivos PCAP."""

    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
    PCAP_MAGIC_NANO = 0xa1b23c4d
    PCAP_MAGIC_NANO_SWAPPED = 0x4d3cb2a1

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets: List[Packet] = []
        self.sessions: Dict[str, Session] = {}
        self.file_handle = None
        self.magic = 0
        self.version_major = 0
        self.version_minor = 0
        self.snaplen = 0
        self.network = 0
        self.swapped = False
        self.nanosecond = False
        self.timestamp = None

    def open(self) -> bool:
        """Abre el archivo PCAP."""
        if not os.path.exists(self.pcap_file):
            logger.error(f"Archivo no encontrado: {self.pcap_file}")
            return False

        try:
            self.file_handle = open(self.pcap_file, "rb")
            if not self._read_header():
                logger.error("Formato PCAP invalido")
                return False
            return True
        except Exception as e:
            logger.error(f"Error al abrir archivo: {e}")
            return False

    def _read_header(self) -> bool:
        """Lee y valida el header PCAP (24 bytes)."""
        header = self.file_handle.read(24)
        if len(header) < 24:
            logger.error(f"Archivo muy pequeño: {len(header)} bytes (necesita 24)")
            return False

        self.magic = struct.unpack("<I", header[0:4])[0]

        if self.magic == 0x0A0D0D0A:
            logger.error("Archivo es PCAPNG, usa PCAPNGReader")
            return False

        if self.magic == self.PCAP_MAGIC:
            self.swapped = False
        elif self.magic == self.PCAP_MAGIC_SWAPPED:
            self.swapped = True
        elif self.magic == self.PCAP_MAGIC_NANO:
            self.swapped = False
            self.nanosecond = True
        elif self.magic == self.PCAP_MAGIC_NANO_SWAPPED:
            self.swapped = True
            self.nanosecond = True
        else:
            logger.error(f"Magic number invalido: {hex(self.magic)}")
            return False

        fmt = "<HHIIII" if not self.swapped else ">HHIIII"
        try:
            values = struct.unpack(fmt, header[4:])
        except struct.error as e:
            logger.error(f"Error al parsear header: {e}")
            return False

        self.version_major = values[0]
        self.version_minor = values[1]
        self.snaplen = values[4]
        self.network = values[5]

        logger.info(f"PCAP abierto: swapped={self.swapped}, v{self.version_major}.{self.version_minor}, "
                  f"snaplen={self.snaplen}, network={self.network}")
        return True

    def read_packets(self) -> List[Packet]:
        """Lee todos los paquetes del archivo."""
        if not self.file_handle:
            if not self.open():
                return []

        self.packets = []
        self.file_handle.seek(24)

        while True:
            packet_header = self.file_handle.read(16)
            if len(packet_header) < 16:
                break

            try:
                if not self.swapped:
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", packet_header)
                else:
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(">IIII", packet_header)
            except struct.error as e:
                logger.warning(f"Error al leer paquete: {e}")
                break

            timestamp = ts_sec + (ts_usec / 1_000_000 if not self.nanosecond else ts_usec / 1_000_000_000)

            if incl_len > 65535 or incl_len == 0:
                logger.warning(f"Longitud de paquete invalida: {incl_len},saltando resto del archivo")
                break

            packet_data = self.file_handle.read(incl_len)
            if len(packet_data) < incl_len:
                logger.warning(f"Paquete incompleto: esperado {incl_len}, recibido {len(packet_data)}")
                break

            packet = self._parse_packet(timestamp, incl_len, orig_len, packet_data)
            if packet:
                self.packets.append(packet)

        logger.info(f"Leidos {len(self.packets)} paquetes")
        
        if self.packets:
            self.timestamp = self.packets[0].timestamp
        
        return self.packets

    def _parse_packet(self, timestamp: float, cap_len: int, orig_len: int, data: bytes) -> Optional[Packet]:
        """Parsea un paquete individual."""
        if len(data) < 14:
            return None

        packet = Packet(
            timestamp=timestamp,
            captured_length=cap_len,
            original_length=orig_len
        )

        offset = 0

        packet.eth_dst = ":".join(f"{b:02x}" for b in data[offset:offset+6])
        packet.eth_src = ":".join(f"{b:02x}" for b in data[offset+6:offset+12])
        offset += 12

        if self.network == 1:
            packet.eth_type = struct.unpack(">H", data[offset:offset+2])[0]
        else:
            packet.eth_type = ETHERNET
        offset += 2

        if packet.eth_type == ETHERNET and len(data) >= offset + 20:
            packet = self._parse_ipv4(packet, data, offset)
        elif packet.eth_type == ETHERNET_IPV6 and len(data) >= offset + 40:
            packet = self._parse_ipv6(packet, data, offset)
        elif packet.eth_type == ETHERNET_ARP and len(data) >= 28:
            packet = self._parse_arp(packet, data, offset)

        return packet

    def _parse_ipv4(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea paquete IPv4."""
        if len(data) < offset + 20:
            return packet

        version_ihl = data[offset]
        ihl = (version_ihl & 0x0F) * 4
        packet.ip_protocol = data[offset+9]

        src_bytes = data[offset+12:offset+16]
        dst_bytes = data[offset+16:offset+20]
        packet.ip_src = ".".join(str(b) for b in src_bytes)
        packet.ip_dst = ".".join(str(b) for b in dst_bytes)
        packet.ip_ttl = data[offset+8]

        protocol = packet.ip_protocol

        if protocol == IPPROTOCOL_TCP and len(data) >= offset + ihl + 20:
            packet = self._parse_tcp(packet, data, offset + ihl)
        elif protocol == IPPROTOCOL_UDP and len(data) >= offset + ihl + 8:
            packet = self._parse_udp(packet, data, offset + ihl)
        elif protocol == IPPROTOCOL_ICMP and len(data) >= offset + ihl + 8:
            packet = self._parse_icmp(packet, data, offset + ihl)

        return packet

    def _parse_ipv6(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea paquete IPv6."""
        if len(data) < offset + 40:
            return packet

        packet.ip_src = self._ipv6_format(data[offset+8:offset+24])
        packet.ip_dst = self._ipv6_format(data[offset+24:offset+40])
        packet.ip_protocol = data[offset+6]
        packet.ip_ttl = data[offset+7]

        return packet

    def _parse_tcp(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea segmento TCP."""
        if len(data) < offset + 20:
            return packet

        packet.protocol = "tcp"
        packet.src_port = struct.unpack(">H", data[offset:offset+2])[0]
        packet.dst_port = struct.unpack(">H", data[offset+2:offset+4])[0]
        packet.tcp_seq = struct.unpack(">I", data[offset+4:offset+8])[0]
        packet.tcp_ack = struct.unpack(">I", data[offset+8:offset+12])[0]
        packet.tcp_flags = data[offset+13]
        packet.tcp_window = struct.unpack(">H", data[offset+14:offset+16])[0]

        return packet

    def _parse_udp(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea datagrama UDP."""
        if len(data) < offset + 8:
            return packet

        packet.protocol = "udp"
        packet.src_port = struct.unpack(">H", data[offset:offset+2])[0]
        packet.dst_port = struct.unpack(">H", data[offset+2:offset+4])[0]
        packet.udp_length = struct.unpack(">H", data[offset+4:offset+6])[0]

        return packet

    def _parse_icmp(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea mensaje ICMP."""
        if len(data) < offset + 8:
            return packet

        packet.protocol = "icmp"
        packet.icmp_type = data[offset]
        packet.icmp_code = data[offset+1]

        return packet

    def _parse_arp(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea paquete ARP."""
        if len(data) < offset + 28:
            return packet

        packet.protocol = "arp"
        opcode = struct.unpack(">H", data[offset+6:offset+8])[0]
        sender_ip = data[offset+14:offset+18]
        target_ip = data[offset+24:offset+28]
        packet.ip_src = ".".join(str(b) for b in sender_ip)
        packet.ip_dst = ".".join(str(b) for b in target_ip)

        return packet

    def _ipv6_format(self, addr: bytes) -> str:
        """Formatea direccion IPv6."""
        parts = []
        for i in range(0, 16, 2):
            parts.append(f"{(addr[i] << 8) | addr[i+1]:x}")
        return ":".join(parts)

    def filter_by_protocol(self, protocol: str) -> List[Packet]:
        """Filtra paquetes por protocolo."""
        return [p for p in self.packets if p.protocol == protocol.lower()]

    def filter_by_ip(self, ip: str, direction: str = "both") -> List[Packet]:
        """Filtra paquetes por direccion IP."""
        results = []
        for p in self.packets:
            if direction == "src" and p.ip_src == ip:
                results.append(p)
            elif direction == "dst" and p.ip_dst == ip:
                results.append(p)
            elif direction == "both" and (p.ip_src == ip or p.ip_dst == ip):
                results.append(p)
        return results

    def filter_by_port(self, port: int, direction: str = "both") -> List[Packet]:
        """Filtra paquetes por puerto."""
        results = []
        for p in self.packets:
            if p.protocol not in ("tcp", "udp"):
                continue
            if direction == "src" and p.src_port == port:
                results.append(p)
            elif direction == "dst" and p.dst_port == port:
                results.append(p)
            elif direction == "both" and (p.src_port == port or p.dst_port == port):
                results.append(p)
        return results

    def get_session(self, src_ip: str, dst_ip: str, src_port: int = 0, dst_port: int = 0) -> Session:
        """Obtiene los paquetes de una sesion."""
        return Session(
            key=f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="tcp",
            packets=[p for p in self.packets
                     if (p.ip_src == src_ip and p.ip_dst == dst_ip and
                         (src_port == 0 or p.src_port == src_port) and
                         (dst_port == 0 or p.dst_port == dst_port))]
        )

    def get_sessions(self) -> Dict[str, Session]:
        """Construye diccionario de sesiones."""
        sessions = {}

        for p in self.packets:
            if p.protocol not in ("tcp", "udp"):
                continue
            if p.src_port == 0 and p.dst_port == 0:
                continue

            key = f"{p.ip_src}:{p.src_port}->{p.ip_dst}:{p.dst_port}"
            if key not in sessions:
                sessions[key] = Session(
                    key=key,
                    src_ip=p.ip_src,
                    dst_ip=p.ip_dst,
                    src_port=p.src_port,
                    dst_port=p.dst_port,
                    protocol=p.protocol,
                    start_time=p.timestamp
                )

            session = sessions[key]
            session.packets.append(p)
            session.packet_count += 1
            session.bytes_sent += p.captured_length

            if p.tcp_flags & TCP_FLAG_SYN:
                session.syn_seen = True
            if p.tcp_flags & TCP_FLAG_SYN and p.tcp_flags & TCP_FLAG_ACK:
                session.synack_seen = True
            if p.tcp_flags & TCP_FLAG_FIN:
                session.fin_seen = True
            if p.tcp_flags & TCP_FLAG_RST:
                session.rst_seen = True

            session.end_time = p.timestamp

        self.sessions = sessions
        return sessions

    def get_stats(self) -> Dict:
        """Obtiene estadisticas del archivo."""
        protocols = {}
        ports = set()
        ips = set()

        for p in self.packets:
            protocols[p.protocol] = protocols.get(p.protocol, 0) + 1
            if p.src_port or p.dst_port:
                ports.add(p.src_port or p.dst_ports)
            if p.ip_src:
                ips.add(p.ip_src)
            if p.ip_dst:
                ips.add(p.ip_dst)

        return {
            "total_packets": len(self.packets),
            "protocols": protocols,
            "unique_ports": len(ports),
            "unique_ips": len(ips),
            "sessions": len(self.sessions)
        }

    def close(self):
        """Cierra el archivo."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()