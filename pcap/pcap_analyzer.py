# =============================================================================
# PCAP Analyzer - Analizador principal de archivos PCAP y logs de red
# =============================================================================
#
# Este modulo es el analizador principal que coordina la lectura de archivos
# PCAP, PCAPNG y logs Zeek, analisis de sesiones y deteccion de ataques.
# Genera eventos compatibles con el servidor SOC.
#
# Uso:
#   python pcap_analyzer.py captura.pcap --server-url https://soc:5000/log --api-key key
#
# Opciones:
#   --format         Formato: auto, pcap, pcapng, zeek
#   --send-to-server  Enviar eventos al servidor SOC
#   --verbose         Salida detallada
#
# =============================================================================

import os
import sys
import json
import logging
import argparse
import hashlib
import time
import requests
from datetime import datetime
from typing import List, Dict, Optional, Set
from collections import defaultdict
from dotenv import load_dotenv
from ipaddress import ip_address, ip_network

from .pcap_reader import PCAPReader
from .pcapng_reader import PCAPNGReader
from .zeek_reader import ZeekReader
from .session_analyzer import SessionAnalyzer
from .attack_detector import AttackDetector
from .compromised_analyzer import CompromisedHostAnalyzer


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PCAPAnalyzer:
    """Analizador principal de archivos PCAP."""

    def __init__(self, input_file: str, input_type: str = "auto"):
        self.input_file = input_file
        self.input_type = input_type
        self.packets = []
        self.connections = []
        self.attacks = []
        self.stats = {}
        self.reader = None
        self.compromised_hosts = {}
        self.forensic_report = {}
        self._processed_hashes: set = self._load_processed_hashes()
        self._internal_networks: Set[str] = set()
        self._packet_timestamps: Dict[str, List[float]] = defaultdict(list)

    def _detect_internal_networks(self):
        """Detecta automáticamente redes privadas del PCAP basándose en RFC 1918."""
        internal_prefixes = {"10.", "192.168.", "172.16.", "172.17.", "172.18.", 
                           "172.19.", "172.2", "172.30.", "172.31."}
        seen_ips = set()
        
        for p in self.packets:
            if hasattr(p, 'ip_src') and p.ip_src:
                seen_ips.add(p.ip_src)
            if hasattr(p, 'ip_dst') and p.ip_dst:
                seen_ips.add(p.ip_dst)
        
        for ip in seen_ips:
            try:
                addr = ip_address(ip)
                if addr.is_private:
                    self._internal_networks.add(ip)
            except:
                pass
        
        logger.debug(f"Redes privadas detectadas: {len(self._internal_networks)} IPs")

    def _is_internal_ip(self, ip: str) -> bool:
        """Determina si una IP es privada usando detección dinámica."""
        if not ip:
            return False
        try:
            return ip_address(ip).is_private
        except:
            return False

    def _get_packet_timestamp(self, src_ip: str, dst_ip: str = None) -> str:
        """Obtiene timestamp del ataque basado en los paquetes."""
        timestamps = []
        
        if src_ip and dst_ip:
            key = f"*:{src_ip}:{dst_ip}"
            timestamps = self._packet_timestamps.get(key, [])
        
        if not timestamps and src_ip:
            key = f"*:{src_ip}:*"
            timestamps = self._packet_timestamps.get(key, [])
        
        if timestamps:
            try:
                from datetime import datetime as dt
                return dt.fromtimestamp(timestamps[0]).isoformat()
            except:
                pass
        
        return self.stats.get("timestamp", datetime.now().isoformat())

    def _collect_packet_timestamps(self):
        """Recolecta timestamps de los paquetes para cada ataque."""
        for p in self.packets:
            ts = getattr(p, 'timestamp', None) or getattr(p, 'ts', None)
            if not ts:
                continue
            
            if hasattr(p, 'ip_src') and p.ip_src:
                key = f"*:{p.ip_src}:*"
                if key not in self._packet_timestamps:
                    self._packet_timestamps[key] = []
                self._packet_timestamps[key].append(ts)
            
            if hasattr(p, 'ip_src') and hasattr(p, 'ip_dst') and p.ip_src and p.ip_dst:
                key = f"*:{p.ip_src}:{p.ip_dst}"
                if key not in self._packet_timestamps:
                    self._packet_timestamps[key] = []
                self._packet_timestamps[key].append(ts)

    def _load_processed_hashes(self) -> set:
        """Carga hashes de archivos ya procesados."""
        state_file = os.path.join(os.path.dirname(__file__), ".processed_pcaps")
        hashes = set()
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                for line in f:
                    hashes.add(line.strip())
        return hashes

    def _save_processed_hash(self, file_hash: str):
        """Guarda hash del archivo procesado."""
        state_file = os.path.join(os.path.dirname(__file__), ".processed_pcaps")
        with open(state_file, "a") as f:
            f.write(f"{file_hash}\n")
        self._processed_hashes.add(file_hash)

    def _get_file_hash(self) -> str:
        """Calcula hash del archivo PCAP."""
        if not os.path.exists(self.input_file):
            return ""
        h = hashlib.sha256()
        with open(self.input_file, "rb") as f:
            h.update(f.read(1024 * 1024))
        return h.hexdigest()[:16]

    def detect_format(self) -> str:
        """Detecta el formato del archivo de entrada."""
        if self.input_type != "auto":
            return self.input_type

        if not os.path.exists(self.input_file):
            raise FileNotFoundError(f"Archivo no encontrado: {self.input_file}")

        ext = os.path.splitext(self.input_file)[1].lower()

        if ext == ".pcapng" or ext == ".ng":
            return "pcapng"
        elif ext == ".pcap" or ext == ".cap":
            return "pcap"
        elif os.path.isdir(self.input_file):
            return "zeek"

        with open(self.input_file, "rb") as f:
            magic = f.read(4)
            if len(magic) >= 4:
                magic_val = int.from_bytes(magic[:4], "little")
                if magic_val == 0x0A0D0D0A:
                    return "pcapng"
                elif magic_val in (0xa1b2c3d4, 0xd4c3b2a1):
                    return "pcap"

        return "pcap"

    def analyze(self) -> Dict:
        """Ejecuta analisis completo."""
        file_hash = self._get_file_hash()
        if file_hash in self._processed_hashes:
            logger.info(f"Archivo ya procesado anteriormente: {file_hash}")
            return {"status": "skipped", "reason": "already_processed", "file_hash": file_hash}

        format_type = self.detect_format()
        logger.info(f"Formato detectado: {format_type}")

        if format_type == "pcap":
            result = self.analyze_pcap()
        elif format_type == "pcapng":
            result = self.analyze_pcapng()
        elif format_type == "zeek":
            result = self.analyze_zeek_logs()
        else:
            raise ValueError(f"Formato no soportado: {format_type}")

        if "error" not in result and file_hash:
            self._save_processed_hash(file_hash)
            logger.info(f"Hash guardado para archivo: {file_hash}")

        return result

    def analyze_pcap(self) -> Dict:
        """Analiza archivo PCAP."""
        logger.info(f"Analizando PCAP: {self.input_file}")

        try:
            reader = PCAPReader(self.input_file)
            if not reader.open():
                logger.error(f"No se pudo abrir el archivo PCAP. Verifica el formato.")
                return {"error": "Invalid PCAP format", "details": "El archivo puede ser PCAPNG o estar corrupto"}

            self.packets = reader.read_packets()
            reader.close()

            if not self.packets:
                logger.warning("No se encontraron paquetes")
                return {"error": "No packets found", "hint": "Archivo puede estar vacío o ser de otro formato"}

            self._detect_internal_networks()
            self._collect_packet_timestamps()

            session_analyzer = SessionAnalyzer(self.packets)
            self.sessions = session_analyzer.build_sessions()

            detector = AttackDetector(packets=self.packets)
            self.attacks = detector.detect_all()

            compromised_analyzer = CompromisedHostAnalyzer(
                packets=self.packets,
                sessions=self.sessions,
                attacks=self.attacks
            )
            self.compromised_hosts = compromised_analyzer.get_compromised_hosts()
            self.forensic_report = compromised_analyzer.generate_forensic_report()

            self.stats = {
                "format": "pcap",
                "total_packets": len(self.packets),
                "total_sessions": len(self.sessions),
                "attacks_detected": len(self.attacks),
                "packets_by_protocol": self._count_protocols(),
                "attacks": [a.to_dict() for a in self.attacks],
                "timestamp": reader.timestamp if reader else None,
                "compromised_hosts": len(self.compromised_hosts),
                "lateral_movements": self.forensic_report.get("summary", {}).get("lateral_movements", 0),
                "forensic": self.forensic_report
            }

            return self.stats

        except Exception as e:
            logger.error(f"Error al analizar PCAP: {e}")
            return {"error": str(e)}

    def analyze_pcapng(self) -> Dict:
        """Analiza archivo PCAPNG."""
        logger.info(f"Analizando PCAPNG: {self.input_file}")

        try:
            reader = PCAPNGReader(self.input_file)
            self.packets = reader.read_packets()
            reader.close()

            if not self.packets:
                logger.warning("No se encontraron paquetes")
                return {"error": "No packets found"}

            session_analyzer = SessionAnalyzer(self.packets)
            self.sessions = session_analyzer.build_sessions()

            detector = AttackDetector(packets=self.packets)
            self.attacks = detector.detect_all()

            compromised_analyzer = CompromisedHostAnalyzer(
                packets=self.packets,
                sessions=self.sessions,
                attacks=self.attacks
            )
            self.compromised_hosts = compromised_analyzer.get_compromised_hosts()
            self.forensic_report = compromised_analyzer.generate_forensic_report()

            self.stats = {
                "format": "pcapng",
                "total_packets": len(self.packets),
                "total_sessions": len(self.sessions),
                "attacks_detected": len(self.attacks),
                "packets_by_protocol": self._count_protocols(),
                "attacks": [a.to_dict() for a in self.attacks],
                "timestamp": reader.timestamp if reader else None,
                "compromised_hosts": len(self.compromised_hosts),
                "forensic": self.forensic_report
            }

            return self.stats

        except Exception as e:
            logger.error(f"Error al analizar PCAPNG: {e}")
            return {"error": str(e)}

    def analyze_zeek_logs(self) -> Dict:
        """Analiza logs Zeek."""
        log_dir = self.input_file
        logger.info(f"Analizando logs Zeek en: {log_dir}")

        try:
            reader = ZeekReader(log_dir)
            reader.read_all_logs(log_dir)

            self.connections = reader.connections

            session_analyzer = SessionAnalyzer()
            session_analyzer.build_sessions_from_zeek(self.connections)

            detector = AttackDetector(connections=self.connections, http_requests=reader.http_requests)
            if hasattr(detector, 'dns_queries'):
                detector.dns_queries = reader.dns_queries

            self.attacks = detector.detect_all()

            self.stats = {
                "format": "zeek",
                "connections": len(self.connections),
                "http_requests": len(reader.http_requests),
                "dns_queries": len(reader.dns_queries),
                "ssl_connections": len(reader.ssl_connections),
                "attacks_detected": len(self.attacks),
                "attacks": [a.to_dict() for a in self.attacks]
            }

            return self.stats

        except Exception as e:
            logger.error(f"Error al analizar Zeek logs: {e}")
            return {"error": str(e)}

    def _count_protocols(self) -> Dict[str, int]:
        """Cuenta paquetes por protocolo."""
        counts = {}
        for p in self.packets:
            proto = p.protocol if hasattr(p, 'protocol') else 'unknown'
            counts[proto] = counts.get(proto, 0) + 1
        return counts

    def get_events(self) -> List[Dict]:
        """Retorna lista de eventos - filtrar por severidad alta."""
        from datetime import datetime as dt_datetime
        events = []
        seen = set()
        
        stats = {
            "total_attacks": len(self.attacks),
            "filtered_low_risk": 0,
            "filtered_no_ip": 0,
            "aggregated": 0,
            "unique_events": 0,
            "by_type": defaultdict(int)
        }

        pcap_global_ts = self.stats.get("timestamp", "")
        if pcap_global_ts:
            try:
                pcap_global_ts = dt_datetime.fromisoformat(pcap_global_ts).isoformat()
            except:
                pcap_global_ts = dt_datetime.now().isoformat()
        else:
            pcap_global_ts = dt_datetime.now().isoformat()

        report_time = dt_datetime.now().isoformat()

        aggregated_events: Dict[str, Dict] = {}

        for attack in self.attacks:
            if attack.risk < 50:
                stats["filtered_low_risk"] += 1
                continue

            src_ip_key = str(attack.src_ip or "")
            if not src_ip_key or src_ip_key == "None":
                stats["filtered_no_ip"] += 1
                continue

            is_internal = self._is_internal_ip(src_ip_key)

            if is_internal and attack.attack_type in ("suspicious_download", "possible_c2"):
                group_key = (attack.attack_type, src_ip_key)
                if group_key not in aggregated_events:
                    stats["aggregated"] += 1
                    stats["by_type"][attack.attack_type] += 1
                    aggregated_events[group_key] = {
                        "attack_type": attack.attack_type,
                        "src_ip": src_ip_key,
                        "dst_ips": set(),
                        "risk": attack.risk,
                        "severity": attack.severity,
                        "evidence": [],
                        "description": attack.description,
                        "mitre_technique": attack.mitre_technique,
                        "protocol": getattr(attack, 'protocol', '') or '',
                        "dst_port": attack.dst_port or 0,
                    }
                if attack.dst_ip:
                    aggregated_events[group_key]["dst_ips"].add(attack.dst_ip)
                if attack.evidence:
                    aggregated_events[group_key]["evidence"].extend(attack.evidence)
            else:
                key = (
                    attack.attack_type,
                    str(attack.src_ip or ""),
                    str(attack.dst_ip or ""),
                    str(attack.dst_port or ""),
                    str(getattr(attack, 'protocol', '') or ""),
                    str(attack.description or "")[:100]
                )
                if key not in seen:
                    seen.add(key)
                    stats["unique_events"] += 1
                    stats["by_type"][attack.attack_type] += 1
                    attack_protocol = getattr(attack, 'protocol', '') or ''
                    
                    attack_ts = self._get_packet_timestamp(str(attack.src_ip or ""), str(attack.dst_ip or ""))
                    
                    extra = {
                        "mitre_technique": attack.mitre_technique,
                        "evidence": attack.evidence,
                        "indicators": attack.indicators,
                        "input_file": self.input_file,
                        "format": self.stats.get("format", "unknown"),
                        "capture_time": self.stats.get("timestamp", ""),
                        "pcap_stats": {
                            "total_packets": self.stats.get("total_packets", 0),
                            "sessions": self.stats.get("total_sessions", 0),
                            "attack_count": self.stats.get("attacks_detected", 0)
                        },
                        "forensic": {
                            "compromised_hosts": self.stats.get("compromised_hosts", 0),
                            "lateral_movements": self.stats.get("lateral_movements", 0)
                        },
                        "attack_info": {
                            "attack_family": attack.attack_type.split("_")[0] if "_" in attack.attack_type else attack.attack_type,
                            "is_c2": attack.attack_type in ["possible_c2", "malware_c2"],
                            "is_download": attack.attack_type == "suspicious_download",
                            "is_lateral": attack.attack_type in ["lateral_movement", "rdp", "ssh", "smb"]
                        }
                    }
                    
                    event = {
                        "agent_id": "pcap-analyzer-01",
                        "src_ip": attack.src_ip or "victim",
                        "src_port": getattr(attack, 'src_port', 0) or 0,
                        "dst_ip": attack.dst_ip,
                        "dst_port": attack.dst_port,
                        "protocol": attack_protocol,
                        "risk": attack.risk,
                        "attack_type": attack.attack_type,
                        "target_host": attack.dst_ip,
                        "target_service": "http" if attack.dst_port in (80, 443) else "unknown",
                        "source": f"pcap_{self.stats.get('format', 'unknown')}",
                        "severity": attack.severity,
                        "event_time": attack_ts,
                        "report_time": report_time,
                        "duration": 0,
                        "raw_log": attack.description,
                        "extra_data": json.dumps(extra)
                    }
                    events.append(event)
                else:
                    unique_ts = self._get_packet_timestamp(str(attack.src_ip or ""), str(attack.dst_ip or ""))
                    seen_unique_key = (attack.attack_type, str(attack.src_ip or ""), str(attack.dst_ip or ""))
                    if seen_unique_key not in seen:
                        seen.add(seen_unique_key)
                        unique_event = {
                            "agent_id": "pcap-analyzer-01",
                            "src_ip": attack.src_ip or "victim",
                            "src_port": getattr(attack, 'src_port', 0) or 0,
                            "dst_ip": attack.dst_ip,
                            "dst_port": attack.dst_port,
                            "protocol": getattr(attack, 'protocol', '') or '',
                            "risk": attack.risk,
                            "attack_type": attack.attack_type,
                            "target_host": attack.dst_ip,
                            "target_service": "http" if attack.dst_port in (80, 443) else "unknown",
                            "source": f"pcap_{self.stats.get('format', 'unknown')}",
                            "severity": attack.severity,
                            "event_time": unique_ts,
                            "report_time": report_time,
                            "duration": 0,
                            "raw_log": attack.description,
                            "extra_data": json.dumps({
                                "mitre_technique": attack.mitre_technique,
                                "evidence": attack.evidence,
                                "indicators": attack.indicators,
                                "input_file": self.input_file,
                                "format": self.stats.get("format", "unknown")
                            })
                        }
                        events.append(unique_event)

        for group_key, data in aggregated_events.items():
            dst_ips_list = list(data["dst_ips"])
            
            attack_ts = self._get_packet_timestamp(data["src_ip"], dst_ips_list[0] if dst_ips_list else None)
            
            extra = {
                "mitre_technique": data["mitre_technique"],
                "evidence": data["evidence"][:5],
                "indicators": {
                    "affected_ips": 1,
                    "all_sources": [data["src_ip"]],
                    "external_ips": dst_ips_list[:10],
                    "count": len(data["evidence"])
                },
                "input_file": self.input_file,
                "format": self.stats.get("format", "unknown"),
                "capture_time": self.stats.get("timestamp", ""),
                "pcap_stats": {
                    "total_packets": self.stats.get("total_packets", 0),
                    "sessions": self.stats.get("total_sessions", 0),
                    "attack_count": self.stats.get("attacks_detected", 0)
                },
                "forensic": {
                    "compromised_hosts": self.stats.get("compromised_hosts", 0),
                    "lateral_movements": self.stats.get("lateral_movements", 0)
                },
                "attack_info": {
                    "is_download": data["attack_type"] == "suspicious_download",
                    "is_c2": data["attack_type"] == "possible_c2"
                }
            }
            
            event = {
                "agent_id": "pcap-analyzer-01",
                "src_ip": data["src_ip"],
                "src_port": 0,
                "dst_ip": dst_ips_list[0] if dst_ips_list else "",
                "dst_port": data["dst_port"],
                "protocol": data["protocol"],
                "risk": min(data["risk"], 100),
                "attack_type": data["attack_type"],
                "target_host": data["src_ip"],
                "target_service": "http" if data["dst_port"] in (80, 443) else "unknown",
                "source": f"pcap_{self.stats.get('format', 'unknown')}",
                "severity": data["severity"],
                "event_time": attack_ts,
                "report_time": report_time,
                "duration": 0,
                "raw_log": data["description"],
                "extra_data": json.dumps(extra)
            }
            events.append(event)

        logger.info(f"Event stats: {dict(stats)}")
        return events

    def send_to_server(self, server_url: str, api_key: str, secret: str = None,
                       verify_ssl: bool = True) -> Dict:
        """Envia eventos al servidor SOC."""
        events = self.get_events()

        if not events:
            logger.info("No hay eventos para enviar")
            return {"status": "no_events"}

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }

        if secret:
            import hmac
            nonce = f"{time.time()}_{os.urandom(8).hex()}"
            timestamp = str(int(time.time()))
            message = f"POST/log{nonce}{timestamp}"
            signature = hmac.new(secret.encode(), message.encode(), "sha256").hexdigest()
            headers["X-Request-ID"] = nonce
            headers["X-Request-Timestamp"] = timestamp
            headers["X-Request-Signature"] = signature

        results = {"sent": 0, "failed": 0, "errors": []}

        logger.info(f"Enviando {len(events)} eventos a {server_url}")

        for i, event in enumerate(events):
            max_retries = 3
            retry_delay = 1

            for attempt in range(max_retries):
                try:
                    logger.debug(f"Evento: {event}")
                    response = requests.post(
                        server_url,
                        json=event,
                        headers=headers,
                        verify=verify_ssl,
                        timeout=30,
                        allow_redirects=False
                    )

                    if response.status_code in (200, 201):
                        results["sent"] += 1
                        logger.info(f"Evento enviado: {event['attack_type']} from {event['src_ip']}")
                        break
                    elif response.status_code == 429:
                        if attempt < max_retries - 1:
                            logger.warning(f"Rate limited, reintento {attempt + 1}/{max_retries} en {retry_delay}s")
                            time.sleep(retry_delay)
                            retry_delay *= 2
                            continue
                        else:
                            results["failed"] += 1
                            results["errors"].append(f"Status {response.status_code} (rate limited)")
                    else:
                        results["failed"] += 1
                        results["errors"].append(f"Status {response.status_code}")
                        break

                except requests.exceptions.Timeout:
                    results["failed"] += 1
                    results["errors"].append("Timeout")
                    break
                except requests.exceptions.ConnectionError:
                    results["failed"] += 1
                    results["errors"].append("Connection error")
                    break
                except Exception as e:
                    results["failed"] += 1
                    results["errors"].append(str(e))
                    break

            if i < len(events) - 1:
                time.sleep(0.3)

        logger.info(f"Resultados: {results['sent']} enviados, {results['failed']} fallidos")
        return results


def main():
    """Funcion principal."""
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

    parser = argparse.ArgumentParser(
        description="Analizador de archivos PCAP para SOC Platform"
    )
    parser.add_argument("input", help="Archivo PCAP/PCAPNG o directorio de logs Zeek")
    parser.add_argument("--format", choices=["auto", "pcap", "pcapng", "zeek"],
                       default=os.getenv("INPUT_FORMAT", "auto"), help="Formato del archivo")
    parser.add_argument("--server-url", help="URL del servidor SOC para enviar eventos",
                       default=os.getenv("SERVER_URL"))
    parser.add_argument("--api-key", help="API key para autenticar con el servidor",
                       default=os.getenv("X_API_KEY"))
    parser.add_argument("--api-secret", help="Secret para firmar requests",
                       default=os.getenv("X_API_KEY_SECRET"))
    parser.add_argument("--verify-ssl", type=lambda x: x.lower() != "false",
                       default=os.getenv("VERIFY_SSL", "true").lower() != "false",
                       help="Verificar certificado SSL")
    parser.add_argument("--output", help="Archivo de salida JSON",
                       default=os.getenv("OUTPUT_FILE"))
    parser.add_argument("--verbose", action="store_true", help="Salida detallada")
    parser.add_argument("--reputation", action="store_true",
                       help="Verificar IP reputation con AbuseIPDB")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.exists(args.input):
        print(f"Error: Archivo no encontrado: {args.input}")
        sys.exit(1)

    analyzer = PCAPAnalyzer(args.input, args.format)
    results = analyzer.analyze()

    if args.reputation:
        from pcap.ip_reputation import check_batch_ips
        events = analyzer.get_events()
        ips = list(set(e.get("dst_ip", "") for e in events if e.get("dst_ip")))
        ips = [ip for ip in ips if ip and not ip.startswith(("10.", "192.168.", "172.", "127."))]

        if ips:
            print(f"Verificando {min(len(ips), 5)} IPs en AbuseIPDB...")
            rep_results = check_batch_ips(ips, max_requests=5)

            for event in events:
                ip = event.get("dst_ip", "")
                if ip in rep_results:
                    rep = rep_results[ip]
                    event["extra_data"]["reputation"] = {
                        "abuse_score": rep.get("abuse_confidence", 0),
                        "total_reports": rep.get("total_reports", 0),
                        "isp": rep.get("isp", ""),
                        "country": rep.get("country_code", "")
                    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Resultados guardados en: {args.output}")

    server_url = args.server_url or os.getenv("SERVER_URL")
    api_key = args.api_key or os.getenv("X_API_KEY")
    api_secret = args.api_secret or os.getenv("X_API_KEY_SECRET")

    if server_url and api_key:
        print(f"Enviando eventos al servidor: {server_url}")
        send_results = analyzer.send_to_server(
            server_url,
            api_key,
            api_secret,
            args.verify_ssl
        )
        print(f"Resultados del envio: {json.dumps(send_results, indent=2)}")

    print(f"\nResumen:")
    print(f"  Paquetes analizados: {results.get('total_packets', results.get('connections', 0))}")
    print(f"  Sesiones: {results.get('total_sessions', 'N/A')}")
    print(f"  Ataques detectados: {results.get('attacks_detected', 0)}")


if __name__ == "__main__":
    main()