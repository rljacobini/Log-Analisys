# =============================================================================
# PCAP Module - Analisis de archivos PCAP para SOC Platform
# =============================================================================

"""
Modulo de analisis de archivos PCAP, PCAPNG y logs Zeek para deteccion de amenazas.

Modulos:
    - pcap_reader: Lectura de archivos PCAP
    - pcapng_reader: Lectura de archivos PCAPNG
    - zeek_reader: Lectura de logs Zeek
    - session_analyzer: Analisis de sesiones de red
    - attack_detector: Deteccion de ataques
    - pcap_analyzer: Analizador principal

Uso:
    from pcap import PCAPAnalyzer

    analyzer = PCAPAnalyzer("captura.pcap")
    results = analyzer.analyze()
"""

__version__ = "1.0.0"

from .pcap_reader import PCAPReader, Packet, Session
from .pcapng_reader import PCAPNGReader
from .zeek_reader import ZeekReader
from .session_analyzer import SessionAnalyzer, SessionStats, AttackEvent
from .attack_detector import AttackDetector, Attack
from .pcap_analyzer import PCAPAnalyzer
from . import config

__all__ = [
    "PCAPReader",
    "PCAPNGReader", 
    "ZeekReader",
    "SessionAnalyzer",
    "AttackDetector",
    "PCAPAnalyzer",
    "Packet",
    "Session",
    "SessionStats",
    "AttackEvent",
    "Attack",
    "config"
]