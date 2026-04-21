# =============================================================================
# PCAPNG Reader - Lectura de archivos PCAPNG (Next Generation)
# =============================================================================
#
# Este modulo lee y parsea archivos PCAPNG, el formato successor de PCAP.
# Soporta multiples secciones e interfaces.
#
# Uso:
#   from pcap.pcapng_reader import PCAPNGReader
#
#   reader = PCAPNGReader("capture.pcapng")
#   packets = reader.read_packets()
#   sections = reader.get_sections()
#
# =============================================================================

import struct
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# =============================================================================
# Constantes PCAPNG
# =============================================================================

PCAPNG_BLOCK_TYPE_SHB = 0x0A0D0D0A  # Section Header Block
PCAPNG_BLOCK_TYPE_IDB = 0x00000001  # Interface Description Block
PCAPNG_BLOCK_TYPE_SPB = 0x00000002  # Simple Packet Block
PCAPNG_BLOCK_TYPE_NRB = 0x00000004  # Name Resolution Block
PCAPNG_BLOCK_TYPE_ISB = 0x00000005  # Interface Statistics Block
PCAPNG_BLOCK_TYPE_EPB = 0x00000006  # Enhanced Packet Block

PCAPNG_CUSTOM_BLOCK_TYPE = 0x00000BAD  # Custom Block (before adoption)


@dataclass
class Section:
    """Representa una seccion PCAPNG."""
    index: int
    start_time: float = 0.0
    end_time: float = 0.0
    snaplen: int = 0


@dataclass
class Interface:
    """Representa una interfaz en PCAPNG."""
    index: int
    link_type: int = 1  # Ethernet
    snap_length: int = 0
    name: str = ""
    description: str = ""


@dataclass
class Packet:
    """Paquete PCAPNG (reutiliza estructura de pcap_reader)."""
    timestamp: float
    captured_length: int
    original_length: int
    interface_id: int = 0
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


class PCAPNGReader:
    """Lectura de archivos PCAPNG."""

    def __init__(self, pcapng_file: str):
        self.pcapng_file = pcapng_file
        self.packets: List[Packet] = []
        self.sections: List[Section] = []
        self.interfaces: Dict[int, Interface] = {}
        self.file_handle = None
        self.byte_order = "<"  # Little endian por defecto
        self.byte_order_mark = 0x1A2B3C4D
        self.timestamp = None

    def open(self) -> bool:
        """Abre el archivo PCAPNG."""
        if not os.path.exists(self.pcapng_file):
            logger.error(f"Archivo no encontrado: {self.pcapng_file}")
            return False

        try:
            self.file_handle = open(self.pcapng_file, "rb")
            if not self._validate_format():
                logger.error("Formato PCAPNG invalido")
                return False
            return True
        except Exception as e:
            logger.error(f"Error al abrir archivo: {e}")
            return False

    def _validate_format(self) -> bool:
        """Valida que sea PCAPNG."""
        magic = self.file_handle.read(4)
        if len(magic) < 4:
            return False

        self.byte_order_mark = struct.unpack("<I", magic)[0]

        if self.byte_order_mark == 0x1A2B3C4D:
            self.byte_order = "<"
        elif self.byte_order_mark == 0x4D3CB2A1:
            self.byte_order = ">"
        else:
            return False

        return True

    def read_packets(self) -> List[Packet]:
        """Lee todos los paquetes del archivo."""
        if not self.file_handle:
            if not self.open():
                return []

        self.packets = []
        self.file_handle.seek(0)

        while True:
            block_data = self._read_next_block()
            if block_data is None:
                break

            block_type = block_data.get("type")
            if block_type == PCAPNG_BLOCK_TYPE_EPB:
                packet_data = block_data.get("data")
                timestamp_high = block_data.get("timestamp_high", 0)
                timestamp_low = block_data.get("timestamp_low", 0)
                timestamp = (timestamp_high << 32) | timestamp_low
                timestamp = timestamp / 1_000_000  # Microsegundos

                captured_len = block_data.get("captured_len", 0)
                packet = self._parse_packet(
                    timestamp,
                    captured_len,
                    block_data.get("original_len", 0),
                    packet_data[:captured_len]
                )
                if packet:
                    packet.interface_id = block_data.get("interface_id", 0)
                    self.packets.append(packet)

        logger.info(f"Leidos {len(self.packets)} paquetes PCAPNG")
        
        if self.packets:
            self.timestamp = self.packets[0].timestamp
        
        return self.packets

    def _read_next_block(self) -> Optional[Dict]:
        """Lee el siguiente bloque PCAPNG."""
        if not self.file_handle:
            return None

        pos = self.file_handle.tell()
        header = self.file_handle.read(12)
        if len(header) < 12:
            return None

        fmt = self.byte_order + " III"
        block_type, block_length, _ = struct.unpack(fmt, header[:12])

        if block_length < 12 or block_length > 10_000_000:
            self.file_handle.seek(pos)
            return None

        block_total = block_length - 12
        block_payload = self.file_handle.read(block_total)

        if block_type == PCAPNG_BLOCK_TYPE_SHB:
            version_major = struct.unpack(self.byte_order + "H", block_payload[0:2])[0]
            version_minor = struct.unpack(self.byte_order + "H", block_payload[2:4])[0]
            section = Section(index=len(self.sections))
            self.sections.append(section)
            logger.info(f"PCAPNG Section: v{version_major}.{version_minor}")
            return {"type": block_type}

        elif block_type == PCAPNG_BLOCK_TYPE_IDB:
            link_type = struct.unpack(self.byte_order + "H", block_payload[0:2])[0]
            snap_length = struct.unpack(self.byte_order + "I", block_payload[4:8])[0]
            interface = Interface(
                index=len(self.interfaces),
                link_type=link_type,
                snap_length=snap_length
            )
            self.interfaces[interface.index] = interface
            return {"type": block_type}

        elif block_type == PCAPNG_BLOCK_TYPE_EPB:
            interface_id = struct.unpack(self.byte_order + "I", block_payload[0:4])[0]
            timestamp_high = struct.unpack(self.byte_order + "I", block_payload[4:8])[0]
            timestamp_low = struct.unpack(self.byte_order + "I", block_payload[8:12])[0]
            captured_len = struct.unpack(self.byte_order + "I", block_payload[12:16])[0]
            original_len = struct.unpack(self.byte_order + "I", block_payload[16:20])[0]

            packet_data = block_payload[20:20+captured_len] if captured_len > 0 else b""

            return {
                "type": block_type,
                "interface_id": interface_id,
                "timestamp_high": timestamp_high,
                "timestamp_low": timestamp_low,
                "captured_len": captured_len,
                "original_len": original_len,
                "data": packet_data
            }

        return {"type": block_type}

    def _parse_packet(self, timestamp: float, cap_len: int, orig_len: int, data: bytes) -> Optional[Packet]:
        """Parsea un paquete desde datos crudos."""
        if len(data) < 14:
            return None

        packet = Packet(
            timestamp=timestamp,
            captured_length=cap_len,
            original_length=orig_len
        )

        packet.eth_dst = ":".join(f"{b:02x}" for b in data[0:6])
        packet.eth_src = ":".join(f"{b:02x}" for b in data[6:12])
        eth_type = struct.unpack(">H", data[12:14])[0]
        packet.eth_type = eth_type

        offset = 14

        if eth_type == 0x0800 and len(data) >= offset + 20:
            packet = self._parse_ipv4(packet, data, offset)
        elif eth_type == 0x86DD and len(data) >= offset + 40:
            packet = self._parse_ipv6(packet, data, offset)
        elif eth_type == 0x0806:
            packet.protocol = "arp"

        return packet

    def _parse_ipv4(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea IPv4 desde datos PCAPNG."""
        if len(data) < offset + 20:
            return packet

        version_ihl = data[offset]
        ihl = (version_ihl & 0x0F) * 4
        packet.ip_protocol = data[offset+9]

        src = data[offset+12:offset+16]
        dst = data[offset+16:offset+20]
        packet.ip_src = ".".join(str(b) for b in src)
        packet.ip_dst = ".".join(str(b) for b in dst)
        packet.ip_ttl = data[offset+8]

        protocol = packet.ip_protocol

        if protocol == 6 and len(data) >= offset + ihl + 20:
            packet.protocol = "tcp"
            tcp_offset = offset + ihl
            packet.src_port = struct.unpack(">H", data[tcp_offset:tcp_offset+2])[0]
            packet.dst_port = struct.unpack(">H", data[tcp_offset+2:tcp_offset+4])[0]
            packet.tcp_seq = struct.unpack(">I", data[tcp_offset+4:tcp_offset+8])[0]
            packet.tcp_ack = struct.unpack(">I", data[tcp_offset+8:tcp_offset+12])[0]
            packet.tcp_flags = data[tcp_offset+13]
        elif protocol == 17 and len(data) >= offset + ihl + 8:
            packet.protocol = "udp"
            packet.src_port = struct.unpack(">H", data[offset+ihl:offset+ihl+2])[0]
            packet.dst_port = struct.unpack(">H", data[offset+ihl+2:offset+ihl+4])[0]
        elif protocol == 1:
            packet.protocol = "icmp"
            packet.icmp_type = data[offset+ihl]
            packet.icmp_code = data[offset+ihl+1]

        return packet

    def _parse_ipv6(self, packet: Packet, data: bytes, offset: int) -> Packet:
        """Parsea IPv6 desde datos PCAPNG."""
        if len(data) < offset + 40:
            return packet

        packet.ip_src = self._ipv6_format(data[offset+8:offset+24])
        packet.ip_dst = self._ipv6_format(data[offset+24:offset+40])
        packet.ip_protocol = data[offset+6]
        packet.ip_ttl = data[offset+7]
        packet.protocol = "ipv6"

        return packet

    def _ipv6_format(self, addr: bytes) -> str:
        """Formatea direccion IPv6."""
        parts = []
        for i in range(0, 16, 2):
            parts.append(f"{(addr[i] << 8) | addr[i+1]:x}")
        return ":".join(parts)

    def get_sections(self) -> List[Section]:
        """Obtiene las secciones del archivo."""
        return self.sections

    def get_interfaces(self) -> Dict[int, Interface]:
        """Obtiene las interfaces del archivo."""
        return self.interfaces

    def filter_by_interface(self, interface_id: int) -> List[Packet]:
        """Filtra paquetes por interfaz."""
        return [p for p in self.packets if p.interface_id == interface_id]

    def filter_by_protocol(self, protocol: str) -> List[Packet]:
        """Filtra paquetes por protocolo."""
        return [p for p in self.packets if p.protocol == protocol.lower()]

    def filter_by_ip(self, ip: str, direction: str = "both") -> List[Packet]:
        """Filtra paquetes por IP."""
        results = []
        for p in self.packets:
            if direction == "src" and p.ip_src == ip:
                results.append(p)
            elif direction == "dst" and p.ip_dst == ip:
                results.append(p)
            elif direction == "both" and (p.ip_src == ip or p.ip_dst == ip):
                results.append(p)
        return results

    def get_stats(self) -> Dict:
        """Obtiene estadisticas."""
        protocols = {}
        for p in self.packets:
            protocols[p.protocol] = protocols.get(p.protocol, 0) + 1

        return {
            "total_packets": len(self.packets),
            "sections": len(self.sections),
            "interfaces": len(self.interfaces),
            "protocols": protocols
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