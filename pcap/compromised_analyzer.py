# =============================================================================
# Compromised Host Analyzer + Forensic
# =============================================================================
#
# Módulo completo para análisis de compromiso y forense:
#   - Detección de equipos comprometidos
#   - Análisis de movimiento lateral
#   - Detección de persistencia
#   - Análisis de red
#   - Análisis de comportamiento
#   - Cadena de ataque (ATT&CK)
#   - Generación de evidencia forense
#   - Recomendaciones de respuesta
#
# Uso:
#   from pcap.compromised_analyzer import CompromisedHostAnalyzer
#   analyzer = CompromisedHostAnalyzer(packets, sessions, attacks)
#   hosts = analyzer.get_compromised_hosts()
#   report = analyzer.generate_forensic_report()
#   timeline = analyzer.get_attack_chain()
#   evidence = analyzer.generate_evidence_package()
#
# =============================================================================

import logging
import json
import hashlib
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from datetime import datetime
import re

logger = logging.getLogger(__name__)


@dataclass
class CompromiseEvent:
    """Evento de compromiso."""
    timestamp: float
    src_ip: str
    dst_ip: str
    event_type: str
    severity: str
    description: str
    evidence: List[str] = field(default_factory=list)
    mitre_technique: str = ""
    malware_indicators: List[str] = field(default_factory=list)


@dataclass
class CompromisedHost:
    """Host comprometido."""
    ip: str
    first_seen: float
    last_seen: float
    compromise_methods: List[str] = field(default_factory=list)
    connections: List[Dict] = field(default_factory=list)
    lateral_movements: List[Dict] = field(default_factory=list)
    credentials_used: List[str] = field(default_factory=list)
    severity: str = "CRITICAL"
    risk_score: int = 100


class CompromisedHostAnalyzer:
    """Analizador de hosts comprometidos."""

    def __init__(self, packets: List = None, sessions: List = None, attacks: List = None):
        self.packets = packets or []
        self.sessions = sessions or []
        self.attacks = attacks or []
        self.compromised_hosts: Dict[str, CompromisedHost] = {}
        self.attack_timeline: List[CompromiseEvent] = []
        self._analyze()

    def _analyze(self):
        """Ejecuta analisis completo."""
        self._identify_compromised_hosts()
        self._analyze_lateral_movement()
        self._analyze_privilege_escalation()
        self._analyze_data_exfiltration()
        self._build_timeline()

    def _identify_compromised_hosts(self):
        """Identifica hosts comprometidos."""
        compromise_indicators = [
            "malware_remote_execution",
            "possible_c2",
            "suspicious_download",
            "shell_access",
            "reverse_shell",
            "meterpreter",
            "psexec",
            "wmi_exec",
            "winrm",
            "ssh",
            "rdp",
            "vnc",
            "remote_access",
            "web_shell",
            "backdoor",
            "rootkit",
            "keylogger",
            "ransomware"
        ]

        for attack in self.attacks:
            if not attack.src_ip:
                continue

            if attack.attack_type in compromise_indicators or attack.risk >= 75:
                src_ip = attack.src_ip
                if src_ip in self.compromised_hosts:
                    host = self.compromised_hosts[src_ip]
                    host.last_seen = max(host.last_seen, getattr(attack, 'timestamp', 0))
                    host.compromise_methods.append(attack.attack_type)
                    if host.severity == "LOW":
                        host.severity = attack.severity
                    host.risk_score = max(host.risk_score, attack.risk)
                else:
                    self.compromised_hosts[src_ip] = CompromisedHost(
                        ip=src_ip,
                        first_seen=getattr(attack, 'timestamp', 0),
                        last_seen=getattr(attack, 'timestamp', 0),
                        compromise_methods=[attack.attack_type],
                        severity=attack.severity,
                        risk_score=attack.risk
                    )

                self.attack_timeline.append(CompromiseEvent(
                    timestamp=getattr(attack, 'timestamp', 0),
                    src_ip=attack.src_ip,
                    dst_ip=attack.dst_ip,
                    event_type=attack.attack_type,
                    severity=attack.severity,
                    description=attack.description,
                    evidence=attack.evidence,
                    mitre_technique=attack.mitre_technique
                ))

    def _analyze_lateral_movement(self):
        """Analiza movimiento lateral."""
        lateral_indicators = [
            "lateral_movement",
            "psexec",
            "winrm",
            "ssh",
            "rdp",
            "smb",
            "wmi",
            "remote_service",
            "shared_creds"
        ]

        for host_ip, host in self.compromised_hosts.items():
            for p in self.packets:
                if p.ip_src == host_ip:
                    if any(ind in str(p.dst_port) for ind in ["3389", "445", "22", "5985", "5986"]):
                        host.lateral_movements.append({
                            "to": p.ip_dst,
                            "port": p.dst_port,
                            "protocol": p.protocol,
                            "timestamp": getattr(p, 'timestamp', 0)
                        })

                    if p.protocol in ("tcp", "udp") and p.dst_port > 0:
                        host.connections.append({
                            "to": p.ip_dst,
                            "port": p.dst_port,
                            "protocol": p.protocol,
                            "timestamp": getattr(p, 'timestamp', 0)
                        })

    def _analyze_privilege_escalation(self):
        """Analiza escalada de privilegios."""
        priv_esc_indicators = [
            "priv_esc",
            "privilege_escalation",
            "sudo",
            "su",
            "getsystem"
        ]

        for host_ip, host in self.compromised_hosts.items():
            for att in host.compromise_methods:
                if any(ind in att.lower() for ind in priv_esc_indicators):
                    host.severity = "CRITICAL"
                    host.risk_score = 100

    def _analyze_data_exfiltration(self):
        """Analiza exfiltracion de datos."""
        for host_ip, host in self.compromised_hosts.items():
            for p in self.packets:
                if p.ip_src == host_ip:
                    if hasattr(p, 'bytes') and p.bytes > 1000000:
                        self.attack_timeline.append(CompromiseEvent(
                            timestamp=getattr(p, 'timestamp', 0),
                            src_ip=host_ip,
                            dst_ip=p.ip_dst,
                            event_type="data_exfiltration",
                            severity="CRITICAL",
                            description=f"Large data transfer: {p.bytes} bytes to {p.ip_dst}",
                            mitre_technique="T1041"
                        ))

    def _build_timeline(self):
        """construye linea de tiempo de ataques."""
        self.attack_timeline.sort(key=lambda x: x.timestamp, reverse=True)

    def get_compromised_hosts(self) -> Dict[str, CompromisedHost]:
        """Retorna hosts comprometidos."""
        return self.compromised_hosts

    def get_attack_timeline(self) -> List[CompromiseEvent]:
        """Retorna linea de tiempo."""
        return self.attack_timeline

    def get_lateral_movements(self) -> List[Dict]:
        """Retorna movimientos laterales."""
        movements = []
        for host in self.compromised_hosts.values():
            movements.extend(host.lateral_movements)
        return movements

    def get_external_connections(self) -> List[Dict]:
        """Retorna conexiones externas de hosts comprometidos."""
        connections = []
        for host in self.compromised_hosts.values():
            for conn in host.connections:
                if conn.get("to", "").startswith(("10.", "192.168.", "172.")):
                    continue
                connections.append(conn)
        return connections

    def generate_forensic_report(self) -> Dict:
        """Genera reporte forense."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_compromised": len(self.compromised_hosts),
                "critical": len([h for h in self.compromised_hosts.values() if h.severity == "CRITICAL"]),
                "lateral_movements": len(self.get_lateral_movements()),
                "external_connections": len(self.get_external_connections())
            },
            "compromised_hosts": [],
            "timeline": [],
            "recommendations": []
        }

        for host in self.compromised_hosts.values():
            report["compromised_hosts"].append({
                "ip": host.ip,
                "first_seen": host.first_seen,
                "last_seen": host.last_seen,
                "severity": host.severity,
                "risk_score": host.risk_score,
                "compromise_methods": list(set(host.compromise_methods)),
                "lateral_movements": len(host.lateral_movements),
                "connections": len(host.connections)
            })

        for event in self.attack_timeline[:50]:
            report["timeline"].append({
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "mitre": event.mitre_technique
            })

        if self.compromised_hosts:
            report["recommendations"] = self._generate_recommendations()

        return report

    def _generate_recommendations(self) -> List[str]:
        """Genera recomendaciones de respuesta."""
        recs = []
        for host in self.compromised_hosts.values():
            if host.severity == "CRITICAL":
                recs.append(f"URGENTE: Aislar equipo {host.ip} - comprometido")
                recs.append(f"Cambiar credenciales del equipo {host.ip}")
            if host.lateral_movements:
                recs.append(f"Revisar equipos destinos de movimiento lateral desde {host.ip}")
            if host.risk_score >= 90:
                recs.append(f"Analisis forense profundo de {host.ip}")

        return list(set(recs))

    def is_compromised(self, ip: str) -> bool:
        """Verifica si una IP esta comprometida."""
        return ip in self.compromised_hosts

    def get_host_details(self, ip: str) -> Optional[Dict]:
        """Retorna detalles de un host comprometido."""
        host = self.compromised_hosts.get(ip)
        if not host:
            return None
        return {
            "ip": host.ip,
            "first_seen": host.first_seen,
            "last_seen": host.last_seen,
            "severity": host.severity,
            "risk_score": host.risk_score,
            "compromise_methods": list(set(host.compromise_methods)),
            "lateral_movements": host.lateral_movements,
            "connections": host.connections
        }

    def get_attack_chain(self) -> Dict:
        """Genera cadena de ataque estilo MITRE ATT&CK."""
        chain = {
            "attack_patterns": [],
            "initial_access": [],
            "execution": [],
            "persistence": [],
            "privilege_escalation": [],
            "defense_evasion": [],
            "credential_access": [],
            "discovery": [],
            "lateral_movement": [],
            "collection": [],
            "exfiltration": [],
            "impact": []
        }

        tactic_mapping = {
            "malware": "initial_access",
            "phishing": "initial_access",
            "suspicious_download": "initial_access",
            "possible_c2": "command_and_control",
            "shell_access": "execution",
            "remote_execution": "execution",
            "reverse_shell": "execution",
            "meterpreter": "execution",
            "backdoor": "persistence",
            "rootkit": "persistence",
            "keylogger": "persistence",
            "registry": "persistence",
            "priv_esc": "privilege_escalation",
            "obfuscation": "defense_evasion",
            "packed": "defense_evasion",
            "keylog": "credential_access",
            "credential_dump": "credential_access",
            "port_scan": "discovery",
            "network_enumeration": "discovery",
            "lateral_movement": "lateral_movement",
            "rdp": "lateral_movement",
            "ssh": "lateral_movement",
            "smb": "lateral_movement",
            "screen_capture": "collection",
            "clipboard": "collection",
            "data_exfiltration": "exfiltration",
            "ransomware": "impact",
            "denial_of_service": "impact",
            "syn_flood": "impact",
            "udp_flood": "impact"
        }

        for event in self.attack_timeline:
            tactic = tactic_mapping.get(event.event_type, "impact")
            if tactic in chain:
                chain[tactic].append({
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "technique": event.event_type,
                    "mitre": event.mitre_technique,
                    "evidence": event.description
                })

        return chain

    def detect_persistence(self) -> List[Dict]:
        """Detecta tecnicas de persistencia."""
        persistence = []
        persist_indicators = [
            ("registry_run", "T1546", "Registry Run Keys"),
            ("scheduled_task", "T1053", "Scheduled Task"),
            ("service", "T1543", "New Service"),
            ("startup", "T1547", "Startup Folder"),
            ("wmi", "T1546", "WMI Event Subscription"),
            ("backdoor", "T1505", "Web Shell/Backdoor"),
            ("rootkit", "T1014", "Rootkit")
        ]

        for event in self.attack_timeline:
            for indicator, mitre, name in persist_indicators:
                if indicator in event.event_type.lower():
                    persistence.append({
                        "ip": event.src_ip,
                        "technique": name,
                        "mitre": mitre,
                        "evidence": event.description
                    })

        return persistence

    def generate_evidence_package(self) -> Dict:
        """Genera paquete de evidencia para forense."""
        evidence = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": "1.0",
                "analysis_type": "network_forensics"
            },
            "summary": {
                "total_events": len(self.attack_timeline),
                "compromised_hosts": len(self.compromised_hosts),
                "attack_chains": self.get_attack_chain()
            },
            "indicators": {
                "ips": list(self.compromised_hosts.keys()),
                "domains": self._extract_domains(),
                "hashes": self._extract_hashes(),
                "ports": self._extract_suspicious_ports()
            },
            "timeline": self._generate_timeline_export(),
            "recommendations": self._generate_recommendations()
        }

        return evidence

    def _extract_domains(self) -> List[str]:
        """Extrae dominios sospechosos."""
        domains = set()
        domain_pattern = re.compile(r'[a-z0-9]+\.[a-z]{2,}')
        for event in self.attack_timeline:
            found = domain_pattern.findall(event.description)
            domains.update(found)
        return list(domains)[:20]

    def _extract_hashes(self) -> List[str]:
        """Extrae hashes de malware."""
        hashes = set()
        hash_patterns = [
            re.compile(r'[a-f0-9]{32}'),
            re.compile(r'[a-f0-9]{40}'),
            re.compile(r'[a-f0-9]{64}')
        ]
        for event in self.attack_timeline:
            for pattern in hash_patterns:
                found = pattern.findall(event.description)
                hashes.update(found)
        return list(hashes)[:20]

    def _extract_suspicious_ports(self) -> List[int]:
        """Extrae puertos sospechosos."""
        ports = set()
        suspicious = [4444, 5555, 6666, 7777, 8888, 31337, 12345, 54321]
        for host in self.compromised_hosts.values():
            for conn in host.connections:
                if conn.get("port") in suspicious:
                    ports.add(conn.get("port"))
        return list(ports)

    def _generate_timeline_export(self) -> List[Dict]:
        """Genera exportacion de timeline."""
        timeline = []
        for event in self.attack_timeline:
            timeline.append({
                "timestamp": event.timestamp,
                "source_ip": event.src_ip,
                "dest_ip": event.dst_ip,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "mitre_id": event.mitre_technique
            })
        return timeline

    def analyze_network_behavior(self, ip: str) -> Dict:
        """Analiza comportamiento de red de un host."""
        host = self.compromised_hosts.get(ip)
        if not host:
            return {"error": "IP not found"}

        behavior = {
            "ip": ip,
            "total_connections": len(host.connections),
            "lateral_movements": len(host.lateral_movements),
            "external_connections": 0,
            "internal_connections": 0,
            "ports_used": set(),
            "protocols": set(),
            "unique_ips": set()
        }

        for conn in host.connections:
            behavior["ports_used"].add(conn.get("port"))
            behavior["protocols"].add(conn.get("protocol"))
            behavior["unique_ips"].add(conn.get("to"))

            dst = conn.get("to", "")
            if dst.startswith(("10.", "192.168.", "172.")):
                behavior["internal_connections"] += 1
            else:
                behavior["external_connections"] += 1

        return {
            "ip": ip,
            "total_connections": behavior["total_connections"],
            "external": behavior["external_connections"],
            "internal": behavior["internal_connections"],
            "unique_ips": len(behavior["unique_ips"]),
            "ports": list(behavior["ports_used"]),
            "risk_level": "HIGH" if behavior["external_connections"] > 10 else "MEDIUM"
        }

    def get_risk_score(self, ip: str) -> int:
        """Calcula score de riesgo para IP."""
        host = self.compromised_hosts.get(ip)
        if not host:
            return 0

        score = host.risk_score

        score += len(host.lateral_movements) * 5
        score += min(len(host.connections), 50)

        for conn in host.connections:
            if not conn.get("to", "").startswith(("10.", "192.168.", "172.")):
                score += 2

        return min(score, 100)