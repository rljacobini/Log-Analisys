# =============================================================================
# PCAP Analyzer - Configuracion
# =============================================================================

import os
from dotenv import load_dotenv

load_dotenv()


# =============================================================================
# Identificacion
# =============================================================================

PCAP_AGENT_ID = os.environ.get("PCAP_AGENT_ID", "pcap-analyzer-01")


# =============================================================================
# Servidor SOC
# =============================================================================

SERVER_URL = os.environ.get("SERVER_URL", "https://localhost:5000/log")
X_API_KEY = os.environ.get("X_API_KEY", "changeme")
X_API_KEY_SECRET = os.environ.get("X_API_KEY_SECRET", "")
USE_SSL = os.environ.get("USE_SSL", "true").lower() == "true"
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() == "true"


# =============================================================================
# Formato de Entrada
# =============================================================================

INPUT_FORMAT = os.environ.get("INPUT_FORMAT", "auto")
ZEEK_LOG_DIR = os.environ.get("ZEEK_LOG_DIR", "")


# =============================================================================
# Analisis
# =============================================================================

ANALYZE_TCP_FLAGS = os.environ.get("ANALYZE_TCP_FLAGS", "true").lower() == "true"
ANALYZE_UDP = os.environ.get("ANALYZE_UDP", "true").lower() == "true"
ANALYZE_ICMP = os.environ.get("ANALYZE_ICMP", "true").lower() == "true"
DETECT_SCANS = os.environ.get("DETECT_SCANS", "true").lower() == "true"
DETECT_BRUTE_FORCE = os.environ.get("DETECT_BRUTE_FORCE", "true").lower() == "true"
DETECT_DOS = os.environ.get("DETECT_DOS", "true").lower() == "true"
DETECT_MITM = os.environ.get("DETECT_MITM", "true").lower() == "true"
DETECT_EXFILTRATION = os.environ.get("DETECT_EXFILTRATION", "true").lower() == "true"


# =============================================================================
# Deteccion
# =============================================================================

PORT_SCAN_THRESHOLD = int(os.environ.get("PORT_SCAN_THRESHOLD", "15"))
SYN_FLOOD_THRESHOLD = int(os.environ.get("SYN_FLOOD_THRESHOLD", "50"))
SYN_FLOOD_WINDOW = float(os.environ.get("SYN_FLOOD_WINDOW", "60.0"))
BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", "5"))
ICMP_FLOOD_THRESHOLD = int(os.environ.get("ICMP_FLOOD_THRESHOLD", "100"))
UDP_FLOOD_THRESHOLD = int(os.environ.get("UDP_FLOOD_THRESHOLD", "100"))
DNS_TUNNELING_QUERY_THRESHOLD = int(os.environ.get("DNS_TUNNELING_QUERY_THRESHOLD", "50"))
DNS_TUNNELING_LENGTH_THRESHOLD = int(os.environ.get("DNS_TUNNELING_LENGTH_THRESHOLD", "100"))
DATA_EXFILTRATION_THRESHOLD = int(os.environ.get("DATA_EXFILTRATION_THRESHOLD", "10000000"))


# =============================================================================
# Rendimiento
# =============================================================================

MAX_PACKETS_MEMORY = int(os.environ.get("MAX_PACKETS_MEMORY", "100000"))
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "300"))


# =============================================================================
# Output
# =============================================================================

OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "")
VERBOSE = os.environ.get("VERBOSE", "false").lower() == "true"


# =============================================================================
# Funciones de Configuracion
# =============================================================================

def get_config() -> dict:
    """Retorna configuracion actual."""
    return {
        "agent_id": PCAP_AGENT_ID,
        "server_url": SERVER_URL,
        "format": INPUT_FORMAT,
        "analyze_tcp": ANALYZE_TCP_FLAGS,
        "analyze_udp": ANALYZE_UDP,
        "analyze_icmp": ANALYZE_ICMP,
        "detect_scans": DETECT_SCANS,
        "detect_brute_force": DETECT_BRUTE_FORCE,
        "detect_dos": DETECT_DOS,
        "detect_mitm": DETECT_MITM,
        "detect_exfiltration": DETECT_EXFILTRATION,
        "port_scan_threshold": PORT_SCAN_THRESHOLD,
        "syn_flood_threshold": SYN_FLOOD_THRESHOLD,
        "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
        "verbose": VERBOSE
    }


def print_config():
    """Imprime configuracion."""
    config = get_config()
    print("=" * 50)
    print("PCAP ANALYZER - Configuracion")
    print("=" * 50)
    for key, value in config.items():
        print(f"  {key}: {value}")
    print("=" * 50)


if __name__ == "__main__":
    print_config()