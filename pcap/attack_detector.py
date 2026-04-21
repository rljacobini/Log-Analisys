# =============================================================================
# Attack Detector - Detector de ataques en trafico de red
# =============================================================================
#
# Este modulo detecta diferentes tipos de ataques en trafico de red usando
# ANALISIS COMPORTAMENTAL (heuristico) - sin hardcodear IPs especificas.
#
# Tipos de deteccion basado en patrones:
#   - Descargas sospechosas (.exe, .dll, .rar, .zip, .js, etc.)
#   - Comportamiento C2 (check-ins periodicos, POSTs a paths inusuales)
#   - Exfiltracion de datos (transferencias grandes)
#   - Puertos no estandar hacia externos
#   - Reconocimiento (many connections to same dest)
#   - patrones de malware conocidos (por URI path, no IP)
#
# Uso:
#   from pcap.attack_detector import AttackDetector
#
#   detector = AttackDetector(packets)
#   attacks = detector.detect_all()
#
# =============================================================================

import logging
import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
import os

logger = logging.getLogger(__name__)


# =============================================================================
# Estructuras de Datos
# =============================================================================

@dataclass
class Attack:
    """Ataque detectado."""
    attack_type: str
    src_ip: str
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    severity: str = "MEDIUM"
    risk: int = 25
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    mitre_technique: str = ""
    indicators: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "attack_type": self.attack_type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "severity": self.severity,
            "risk": self.risk,
            "description": self.description,
            "evidence": self.evidence,
            "mitre": self.mitre_technique,
            "indicators": self.indicators
        }


# =============================================================================
# Constantes MITRE ATT&CK v14 (COMPLETO)
# =============================================================================

MITRE_TECHNIQUES = {
    # TA0001: Initial Access
    "phishing": "T1566",
    "spearphishing": "T1566",
    "drive_by_compromise": "T1189",
    "exploit_public_facing": "T1190",
    "supply_chain": "T1195",
    "valid_accounts": "T1078",
    "external_remote_services": "T1133",
    "trusted_relationship": "T1198",
    " Spearphishing Attachment": "T1566",
    " Spearphishing Link": "T1566",
    " Spearphishing Voice": "T1566",
    " Hardware Additions": "T1200",
    " Exploit Internal Service": "T1190",
    " System Proxy": "T1080",

    # TA0002: Execution
    "malware_execution": "T1204",
    "scripting": "T1059",
    "command_api": "T1202",
    "native_api": "T1106",
    "user_execution": "T1204",
    "PowerShell": "T1059",
    "Windows Command Shell": "T1059",
    "Process Injection": "T1055",
    "Exploits": "T1068",
    "Scripting": "T1059",
    "Python": "T1059",
    "JavaScript": "T1059",
    "VBScript": "T1059",
    "Launch Daemon": "T1569",
    "LSASS": "T1003",
    "Scheduled Task": "T1053",
    "Service Execution": "T1569",

    # TA0003: Persistence
    "boot_autostart": "T1547",
    "registry_run": "T1546",
    "scheduled_task": "T1053",
    "service_create": "T1543",
    "wmi_event": "T1546",
    "Startup Folder": "T1547",
    "Registry Autorun": "T1546",
    "Scheduled Task": "T1053",
    "Service Registry": "T1543",
    "DLL Search Order Hijack": "T1574",
    "Side Loading": "T1574",
    "Startup Items": "T1547",
    "Winlogon": "T1547",
    "Time Providers": "T1547",
    "cron": "T1053",
    "Systemd": "T1543",
    "Web Shell": "T1505",
    "Tiger": "T1200",

    # TA0004: Privilege Escalation
    "priv_esc": "T1068",
    "suid": "T1166",
    "valid_accounts": "T1078",
    "Exploitation": "T1068",
    "sudo": "T1166",
    "setuid": "T1166",
    "Scheduled Task": "T1053",
    "Service": "T1611",
    "DLL Search Order": "T1574",
    "Accessibility Features": "T1546",
    "AppInit DLLs": "T1546",
    "Application Shimming": "T1546",
    "File System Permissions": "T1544",
    "Path Interception": "T1574",
    "Parent PID Spoofing": "T1134",
    "Elevated Execution": "T1068",

    # TA0005: Defense Evasion
    "obfuscation": "T1027",
    "packed": "T1045",
    "anti_debug": "T1064",
    "disable_security": "T1562",
    "masquerade": "T1036",
    "LSASS": "T1003",
    "Disable or Modify Tools": "T1562",
    "Disable Windows Event Logging": "T1562",
    "Indicator Removal": "T1070",
    " Timestamps": "T1070",
    " File Deletion": "T1070",
    " Clear Windows Event Log": "T1562",
    " Modify Registry": "T1112",
    " Obfuscated Files": "T1027",
    " Encrypted Data": "T1027",
    " Steganography": "T1027",
    " Runtime Data Manipulation": "T1027",
    " Virtualization/Sandbox": "T1492",
    " Binary Padding": "T1027",
    " Software Packing": "T1045",
    " Modify System Time": "T1070",
    " Modify ACL": "T1222",
    " Component Disable": "T1562",

    # TA0006: Credential Access
    "keylog": "T1056",
    "credential_dump": "T1003",
    "browser_dump": "T1005",
    "wireless": "T1040",
    "two_factor": "T1111",
    "LSASS": "T1003",
    "SAM": "T1003",
    "Cached Credentials": "T1003",
    "Credential Scanning": "T1005",
    "Private Keys": "T1005",
    "Password Filter": "T1556",
    "Securityd": "T1556",
    "Process Discovery": "T1057",
    "Network Sniffing": "T1040",
    "Kerberoasting": "T1005",
    "Silver Ticket": "T1005",
    "Golden Ticket": "T1005",
    "DCSync": "T1003",
    "Credential Reuse": "T1078",
    "Credentials in Files": "T1005",
    "Credentials in Registry": "T1005",
    "Bash History": "T1005",

    # TA0007: Discovery
    "port_scan": "T1046",
    "network_discovery": "T1046",
    "system_discovery": "T1082",
    "process_discovery": "T1057",
    "file_discovery": "T1083",
    "Account Discovery": "T1087",
    "Local Group Discovery": "T1069",
    "Domain Group Discovery": "T1069",
    "System Info": "T1082",
    "System Network Configuration": "T1082",
    "System Network Connections": "T1046",
    "System Owner/User Discovery": "T1082",
    "Virtualization Detection": "T1492",
    "Virtualization/Sandbox": "T1492",

    # TA0008: Lateral Movement
    "lateral_movement": "T1021",
    "remote_service": "T1021",
    "shared_creds": "T1078",
    "ssh": "T1021",
    "SMB/Windows Admin Shares": "T1021",
    "Remote Desktop": "T1021",
    "VNC": "T1021",
    "Windows Remote Management": "T1021",
    "SSH": "T1021",
    "RDP": "T1021",
    "SMB": "T1021",
    "Distributed Component Object Model": "T1021",
    "Exploitation of Vulnerability": "T1190",

    # TA0009: Collection
    "screen_capture": "T1113",
    "audio_capture": "T1123",
    "email_collect": "T1114",
    "clipboard": "T1115",
    "Browser": "T1005",
    "Keylogging": "T1056",
    "Screen Capture": "T1113",
    "Audio Capture": "T1123",
    "Clipboard": "T1115",
    "Email Collection": "T1114",
    "Local Data Staging": "T1074",
    "Remote Data Staging": "T1074",

    # TA0011: Command and Control
    "c2": "T1071",
    "dns_c2": "T1071",
    "http_c2": "T1071",
    "encoded_c2": "T1132",
    "multi_stage": "T1104",
    "DNS": "T1071",
    "HTTP/HTTPS": "T1071",
    "FTP": "T1071",
    "SMTP": "T1071",
    "IRC": "T1071",
    "Web Protocols": "T1071",
    "Proxy": "T1090",
    "Multi-Stage": "T1104",
    "Remote Access": "T1219",
    "Data Encoding": "T1132",
    "Data Obfuscation": "T1001",
    "Non-Application Layer": "T1095",
    "Multi-Stage Channels": "T1104",
    "Web Service": "T1104",

    # TA0010: Exfiltration
    "data_exfiltration": "T1041",
    "auto_exfil": "T1041",
    "scheduled_exfil": "T1041",
    "Exfiltration Over Alternative Protocol": "T1041",
    "Exfiltration Over C2 Channel": "T1041",
    "Data Staged": "T1074",
    "Automated Exfiltration": "T1041",
    "Data Compressed": "T1002",
    "Data Encrypted": "T1002",
    "Transfer to Cloud": "T1041",

    # TA0040: Impact
    "ransomware": "T1486",
    "denial_of_service": "T1498",
    "service_stop": "T1489",
    "disk_wipe": "T1488",
    "data_encryption": "T1486",
    "syn_flood": "T1498",
    "udp_flood": "T1498",
    "icmp_flood": "T1498",
    "Endpoint Denial": "T1498",
    "Service Stop": "T1489",
    "Data Destruction": "T1488",
    "Data Encrypted for Impact": "T1486",
    "Inhibit Recovery": "T1490",
    "OS Boot Recovery": "T1490",
    "Network DoS": "T1498",
    "Disk Wipe": "T1488",
    "File Delete": "T1488",
    "Disk Content Wipe": "T1488",

    # Network Effects (TA0035)
    "arp_spoofing": "T1557",
    "dns_poisoning": "T1651",
    "mac_spoofing": "T1549",
    "dhcp_spoofing": "T1557",
    "DNS": "T1588",
    "ICMP": "T1588",
    "Man in the Middle": "T1557",
    "ARP Cache Poison": "T1557",
    "IPv4/IPv6": "T1588",

    # Web Attacks
    "sql_injection": "T1190",
    "xss": "T1183",
    "web_shell": "T1505",
    "buffer_overflow": "T1055",
    "Web Attack": "T1189",
    "Injection": "T1190",
    "XSS": "T1183",
    "Webshell": "T1505",
    "Arbitrary File Upload": "T1105",
    "Server Side Include": "T1505",
    "Cross-Site Scripting": "T1183",

    # Others
    "brute_force": "T1110",
    "webshell": "T1505",
    "malware_download": "T1105",
    "malware_c2": "T1071",
    "cryptojacking": "T1496",
    "weak_crypto": "T1588",
    "cleartext_creds": "T1078",
    "Exfiltration": "T1041",
    "Automated Impact": "T1588",
    "Financial Theft": "T1588",
    "Hardware": "T1588",
    "ransomware_note": "T1486",
    "Dataencrypted": "T1486"
}

MALWARE_URI_PATTERNS = {
    "ursnif": {
        "name": "Ursnif/Gozi/ISFB",
        "uri_patterns": [r"/wp-content/.*\.php", r"/cgi-bin/.*\.php"],
        "mitre": "T1071",
        "severity": 90
    },
    "trickbot": {
        "name": "Trickbot",
        "uri_patterns": [r"/update/.*\.php", r"/gate/.*\.php", r"/TDSS"],
        "mitre": "T1071",
        "severity": 90
    },
    "emotet": {
        "name": "Emotet",
        "uri_patterns": [r"/process\.php", r"/login\.php", r"/myform"],
        "mitre": "T1071",
        "severity": 95
    },
    "dridex": {
        "name": "Dridex",
        "uri_patterns": [r"/invoice/.*", r"/payment/.*", r"/api/.*\?auth"],
        "mitre": "T1071",
        "severity": 90
    },
    "hancitor": {
        "name": "Hancitor",
        "uri_patterns": [r"/doc/.*\.exe", r"/files/.*\.dll", r"/load/"],
        "mitre": "T1105",
        "severity": 85
    },
    "cobalt_strike": {
        "name": "Cobalt Strike",
        "uri_patterns": [r"/ab[.]php", r"/[.]png", r"/sleep", r"/[.]jpg\?id=", r"/pixel"],
        "mitre": "T1071",
        "severity": 100
    },
    "icedid": {
        "name": "IcedID",
        "uri_patterns": [r"/checkin", r"/verify", r"/log[.]php", r"/submit"],
        "mitre": "T1071",
        "severity": 90
    },
    "lumma": {
        "name": "Lumma Stealer",
        "uri_patterns": [r"/config", r"/bin/.*\.dat", r"/c2/"],
        "mitre": "T1071",
        "severity": 90
    },
    "netsupport": {
        "name": "NetSupport Manager RAT",
        "uri_patterns": [r"/nsm", r"/client", r"/nsms/"],
        "mitre": "T1071",
        "severity": 95
    },
    "asyncrat": {
        "name": "AsyncRAT",
        "uri_patterns": [r"/a[.]php", r"/panel", r"/system/"],
        "mitre": "T1071",
        "severity": 85
    },
    "quasar": {
        "name": "Quasar RAT",
        "uri_patterns": [r"/q[.]php", r"/host", r"/binary"],
        "mitre": "T1071",
        "severity": 80
    },
    "raccoon": {
        "name": "Raccoon Stealer",
        "uri_patterns": [r"/gate", r"/store", r"/grabber"],
        "mitre": "T1071",
        "severity": 80
    },
    "record_loader": {
        "name": "Record Loader",
        "uri_patterns": [r"/record/.*\.js", r"/play"],
        "mitre": "T1105",
        "severity": 85
    },
    "remcos": {
        "name": "Remcos RAT",
        "uri_patterns": [r"/remcos", r"/bot/.*\.php", r"/new/"],
        "mitre": "T1071",
        "severity": 90
    },
    "njrat": {
        "name": "njRAT",
        "uri_patterns": [r"/nj", r"/rat/.*\.php", r"/client/"],
        "mitre": "T1071",
        "severity": 85
    },
    "nanocore": {
        "name": "NanoCore RAT",
        "uri_patterns": [r"/nano", r"/core/.*\.php", r"/plugins/"],
        "mitre": "T1071",
        "severity": 85
    },
    "formbook": {
        "name": "Formbook",
        "uri_patterns": [r"/api/.*log", r"/data/.*collect", r"/send\?cmd="],
        "mitre": "T1071",
        "severity": 85
    },
    "agentTesla": {
        "name": "Agent Tesla",
        "uri_patterns": [r"/sendlog", r"/upload/.*data", r"/keylog"],
        "mitre": "T1071",
        "severity": 85
    },
    "snake_keylogger": {
        "name": "Snake Keylogger",
        "uri_patterns": [r"/snake", r"/log/.*\.txt", r"/report"],
        "mitre": "T1071",
        "severity": 80
    },
    "redline": {
        "name": "RedLine Stealer",
        "uri_patterns": [r"/redline", r"/grab/.*\.dat", r"/config"]
    },
    "warzone": {
        "name": "Warzone RAT",
        "uri_patterns": [r"/warzone", r"/admin/.*\.php", r"/az"]
    },
    "silent": {
        "name": "Silent RAT",
        "uri_patterns": [r"/silent", r"/s/.*\.php"]
    },
    "revenge": {
        "name": "RevengeRAT",
        "uri_patterns": [r"/rev", r"/socket", r"/connect"]
    },
    "socg": {
        "name": "SOCGholic Loader",
        "uri_patterns": [r"/socg", r"/stub"]
    },
    "darkcloud": {
        "name": "DarkCloud Loader",
        "uri_patterns": [r"/darkcloud", r"/panel"]
    },
    "mpgh": {
        "name": "MPGH Dropper",
        "uri_patterns": [r"/mpgh", r"/free"]
    },
    "SystemData": {
        "name": "SystemData Loader",
        "uri_patterns": [r"/sys|dat", r"/d/.*"]
    },
    "tesladrypta": {
        "name": "TeslaCrypt",
        "uri_patterns": [r"/tesla", r"/enc", r"/key"],
        "mitre": "T1486",
        "severity": 95
    },
    "locky": {
        "name": "Locky Ransomware",
        "uri_patterns": [r"/locky", r"/payment/.*", r"/invoice\.php"],
        "mitre": "T1486",
        "severity": 95
    },
    "Cerber": {
        "name": "Cerber Ransomware",
        "uri_patterns": [r"/cerber", r"/gate/.*", r"/read"],
        "mitre": "T1486",
        "severity": 95
    },
    "ryuk": {
        "name": "Ryuk Ransomware",
        "uri_patterns": [r"/ryuk", r"/auth", r"/check"],
        "mitre": "T1486",
        "severity": 100
    },
    "maze": {
        "name": "Maze Ransomware",
        "uri_patterns": [r"/maze", r"/info", r"/step"],
        "mitre": "T1486",
        "severity": 100
    },
    "revil": {
        "name": "REvil/Sodinokibi",
        "uri_patterns": [r"/revil", r"/sodin", r"/ decrypt"],
        "mitre": "T1486",
        "severity": 100
    },
    "clop": {
        "name": "Clop Ransomware",
        "uri_patterns": [r"/clop", r"/panel", r"/news"],
        "mitre": "T1486",
        "severity": 100
    },
    "darkside": {
        "name": "DarkSide Ransomware",
        "uri_patterns": [r"/darkside", r"/dark", r"/main"],
        "mitre": "T1486",
        "severity": 100
    },
    "blackmatter": {
        "name": "BlackMatter Ransomware",
        "uri_patterns": [r"/blackmatter", r"/login", r"/sup"],
        "mitre": "T1486",
        "severity": 100
    },
    "conti": {
        "name": "Conti Ransomware",
        "uri_patterns": [r"/conti", r"/secure", r"/check"],
        "mitre": "T1486",
        "severity": 100
    },
    "trickster": {
        "name": "Trickster",
        "uri_patterns": [r"/trickster", r"/verify"]
    },
    "purebot": {
        "name": "PureBot",
        "uri_patterns": [r"/pure", r"/bot", r"/get"]
    },
    "pony": {
        "name": "Pony Stealer",
        "uri_patterns": [r"/pony", r"/grab", r"/logs"]
    },
    "azorult": {
        "name": "Azorult",
        "uri_patterns": [r"/azor", r"/data", r"/config"]
    },
    "risiprox": {
        "name": "RisiProxy",
        "uri_patterns": [r"/risi", r"/proxy"]
    },
    "patriot": {
        "name": "Patriot",
        "uri_patterns": [r"/patriot", r"/run"]
    },
    "obsidium": {
        "name": "Obsidium",
        "uri_patterns": [r"/obsi", r"/dll"]
    },
    "smth": {
        "name": "Smth Stealer",
        "uri_patterns": [r"/smth", r"/stealer"]
    },
    "masslogger": {
        "name": "MassLogger",
        "uri_patterns": [r"/mass", r"/log"]
    },
    "叔叔": {
        "name": "Uncle Sam RAT",
        "uri_patterns": [r"/uncle", r"/sam"]
    },
    "ksdk": {
        "name": "Koidra RAT",
        "uri_patterns": [r"/koid", r"/ksdk"]
    },
    "bittor": {
        "name": "Bittor RAT",
        "uri_patterns": [r"/bittor", r"/bt"]
    },
    "crossline": {
        "name": "Crossline RAT",
        "uri_patterns": [r"/cross", r"/line"]
    },
    "caesar": {
        "name": "Caesar RAT",
        "uri_patterns": [r"/caesar", r"/xor"]
    },
    "弑神": {
        "name": "Rodent",
        "uri_patterns": [r"/rodent", r"/rat"]
    },
    "dend": {
        "name": "DenD",
        "uri_patterns": [r"/dend", r"/backdoor"]
    },
    "loxi": {
        "name": "Loxim",
        "uri_patterns": [r"/lox", r"/im"]
    },
    "gandrum": {
        "name": "GandCrab",
        "uri_patterns": [r"/gand", r"/crab", r"/decrypt"]
    },
    "emotet_loader": {
        "name": "Emotet Loader",
        "uri_patterns": [r"/emotet", r"/e2.php", r"/e3.php"]
    },
    "hecate": {
        "name": "Hancitor/HEX",
        "uri_patterns": [r"/hecate", r"/hex", r"/panel"]
    },
    "icedid_loader": {
        "name": "IcedID Loader",
        "uri_patterns": [r"/icedid", r"/bot"]
    },
    "qakbot": {
        "name": "Qakbot/QBot",
        "uri_patterns": [r"/qakbot", r"/qbot", r"/login"]
    },
    "icedID": {
        "name": "Banking Trojan",
        "uri_patterns": [r"/bank", r"/verify\.php", r"/api"]
    },
    "cryptbot": {
        "name": "Cryptbot",
        "uri_patterns": [r"/crypt", r"/step"]
    },
    "infoztealer": {
        "name": "InfoStealer",
        "uri_patterns": [r"/infos", r"/stealer"]
    },
    "eclipse": {
        "name": "Eclipse",
        "uri_patterns": [r"/eclipse", r"/moon"]
    },
    "moonshield": {
        "name": "MoonShield",
        "uri_patterns": [r"/moon", r"/shield"]
    },
    "guLoader": {
        "name": "GuLoader",
        "uri_patterns": [r"/guloader", r"/load"]
    },
    "ICBIN": {
        "name": "ICBIN Loader",
        "uri_patterns": [r"/icbin", r"/cbin"]
    },
    "coldcap": {
        "name": "Coldcap Loader",
        "uri_patterns": [r"/coldcap", r"/cold"]
    },
    "wab": {
        "name": "WAB Loader",
        "uri_patterns": [r"/wab", r"/loader"]
    },
    "vidar": {
        "name": "Vidar Stealer",
        "uri_patterns": [r"/vidar", r"/grab"]
    },
    "arkei": {
        "name": "Arkei Stealer",
        "uri_patterns": [r"/arkei", r"/steal"]
    },
    "tria": {
        "name": "Tria Stealer",
        "uri_patterns": [r"/tria", r"/log"]
    },
    "nost": {
        "name": "Noat Stealer",
        "uri_patterns": [r"/noat", r"/data"]
    },
    "eamless": {
        "name": "Eamless",
        "uri_patterns": [r"/eamless", r"/emp"]
    },
    "blocker": {
        "name": "Blocker",
        "uri_patterns": [r"/block", r"/lock"]
    },
    "gimemo": {
        "name": "GiMeNow",
        "uri_patterns": [r"/gime", r"/now"]
    },
    "mruptor": {
        "name": "Miruptor",
        "uri_patterns": [r"/mruptor", r"/run"]
    },
    "orange": {
        "name": "Orange Spam",
        "uri_patterns": [r"/orange", r"/spam"]
    },
    "hured": {
        "name": "HuRup",
        "uri_patterns": [r"/hured", r"/upd"]
    },
    "rapim": {
        "name": "Rapid",
        "uri_patterns": [r"/rapid", r"/rat"]
    },
    "darkc": {
        "name": "DarkCrystal",
        "uri_patterns": [r"/darkc", r"/crystal"]
    },
    "darkcre": {
        "name": "DarkCre",
        "uri_patterns": [r"/darkcre", r"/cre"]
    },
    "cryptom": {
        "name": "Cryptom",
        "uri_patterns": [r"/crypto", r"/miner"]
    },
    "cryptominer": {
        "name": "Cryptominer",
        "uri_patterns": [r"/mine", r"/pool", r"/stratum"]
    },
    "xmrig": {
        "name": "XMRig Miner",
        "uri_patterns": [r"/xmrig", r"/static"]
    },
    "coinhive": {
        "name": "CoinHive",
        "uri_patterns": [r"/coinhive", r"/miner"]
    },
    "beacon": {
        "name": "Cobalt Strike Beacon",
        "uri_patterns": [r"/beacon", r"/ab", r"/aid"]
    },
    "session": {
        "name": "Session Stealer",
        "uri_patterns": [r"/session", r"/cookie"]
    },
    "browser": {
        "name": "Browser Stealer",
        "uri_patterns": [r"/browser", r"/history"]
    },
    "password": {
        "name": "Password Stealer",
        "uri_patterns": [r"/password", r"/save"]
    },
    # 2024-2025 Advanced Malware
    "async": {
        "name": "AsyncRAT",
        "uri_patterns": [r"/async", r"/a/rat", r"/connect"],
        "mitre": "T1071",
        "severity": 95
    },
    "dark": {
        "name": "Dark RAT",
        "uri_patterns": [r"/dark/rat", r"/dRat", r"/shadow"],
        "mitre": "T1071",
        "severity": 95
    },
    "verse": {
        "name": "VerseStealer",
        "uri_patterns": [r"/verse", r"/collect", r"/grab"],
        "mitre": "T1071",
        "severity": 90
    },
    "sDelay": {
        "name": "sDelay RAT",
        "uri_patterns": [r"/sdelay", r"/delay", r"/back"],
        "mitre": "T1071",
        "severity": 90
    },
    "turb": {
        "name": "Turbo RAT",
        "uri_patterns": [r"/turbo", r"/turb", r"/run"],
        "mitre": "T1071",
        "severity": 90
    },
    "lotus": {
        "name": "Lotus Stealer",
        "uri_patterns": [r"/lotus", r"/steal", r"/loot"],
        "mitre": "T1071",
        "severity": 90
    },
    "rise": {
        "name": "Rise Pro",
        "uri_patterns": [r"/rise", r"/pro", r"/api"],
        "mitre": "T1071",
        "severity": 90
    },
    "lunar": {
        "name": "Lunar",
        "uri_patterns": [r"/lunar", r"/moon"],
        "mitre": "T1071",
        "severity": 85
    },
    "aurora": {
        "name": "Aurora Stealer",
        "uri_patterns": [r"/aurora", r"/ steal"],
        "mitre": "T1071",
        "severity": 90
    },
    "solar": {
        "name": "SolarMarker",
        "uri_patterns": [r"/solar", r"/marker", r"/book"],
        "mitre": "T1071",
        "severity": 90
    },
    "mythic": {
        "name": "Mythic RAT",
        "uri_patterns": [r"/mythic", r"/api/v1", r"/callback"],
        "mitre": "T1071",
        "severity": 95
    },
    "andest": {
        "name": "Andes RAT",
        "uri_patterns": [r"/andes", r"/and", r"/connect"],
        "mitre": "T1071",
        "severity": 90
    },
    "insidem": {
        "name": "InsideRAT",
        "uri_patterns": [r"/inside", r"/insideRAT"],
        "mitre": "T1071",
        "severity": 90
    },
    "pure": {
        "name": "Pure Logs",
        "uri_patterns": [r"/pure", r"/pl", r"/logs"],
        "mitre": "T1071",
        "severity": 85
    },
    "hook": {
        "name": "HookBot",
        "uri_patterns": [r"/hook", r"/bot", r"/inj"],
        "mitre": "T1071",
        "severity": 90
    },
    "steel": {
        "name": "SteelFox",
        "uri_patterns": [r"/steelfox", r"/fox"],
        "mitre": "T1071",
        "severity": 85
    },
    "icc": {
        "name": "ICC Bot",
        "uri_patterns": [r"/icc", r"/iccb"],
        "mitre": "T1071",
        "severity": 85
    },
    "gac": {
        "name": "GAC Stealer",
        "uri_patterns": [r"/gac", r"/get"],
        "mitre": "T1071",
        "severity": 85
    },
    "nano": {
        "name": "NanoCore",
        "uri_patterns": [r"/nano", r"/client"],
        "mitre": "T1071",
        "severity": 85
    },
    "skype": {
        "name": "Skype RAT",
        "uri_patterns": [r"/skype", r"/skyp"],
        "mitre": "T1071",
        "severity": 85
    },
    "spade": {
        "name": "Spade",
        "uri_patterns": [r"/spade", r"/c2"],
        "mitre": "T1071",
        "severity": 90
    },
    "cere": {
        "name": "Ceres RAT",
        "uri_patterns": [r"/ceres", r"/cere"],
        "mitre": "T1071",
        "severity": 90
    },
    "grease": {
        "name": "Grease",
        "uri_patterns": [r"/grease", r"/fast"],
        "mitre": "T1071",
        "severity": 85
    },
    "hbase": {
        "name": "HBase",
        "uri_patterns": [r"/hbase", r"/hb"],
        "mitre": "T1071",
        "severity": 85
    },
    "tebot": {
        "name": "Teboga",
        "uri_patterns": [r"/tebot", r"/tb"],
        "mitre": "T1071",
        "severity": 85
    },
    "acorn": {
        "name": "Acorn RAT",
        "uri_patterns": [r"/acorn", r"/ac"],
        "mitre": "T1071",
        "severity": 85
    },
    "pear": {
        "name": "Pear RAT",
        "uri_patterns": [r"/pear", r"/pr"],
        "mitre": "T1071",
        "severity": 85
    },
    "acd": {
        "name": "AcidoRAT",
        "uri_patterns": [r"/acido", r"/acid"],
        "mitre": "T1071",
        "severity": 90
    },
    "guloader": {
        "name": "GuLoader",
        "uri_patterns": [r"/guloader", r"/gu", r"/load"],
        "mitre": "T1105",
        "severity": 95
    },
    "titan": {
        "name": "Titan",
        "uri_patterns": [r"/titan", r"/tita"],
        "mitre": "T1071",
        "severity": 95
    },
    "blood": {
        "name": "BloodRAT",
        "uri_patterns": [r"/blood", r"/bd"],
        "mitre": "T1071",
        "severity": 90
    },
    "swift": {
        "name": "Swift",
        "uri_patterns": [r"/swift", r"/sw"],
        "mitre": "T1071",
        "severity": 90
    },
    "blueling": {
        "name": "BlueLing",
        "uri_patterns": [r"/blueling", r"/bl"],
        "mitre": "T1071",
        "severity": 85
    },
    "mole": {
        "name": "MoleRAT",
        "uri_patterns": [r"/mole", r"/ml"],
        "mitre": "T1071",
        "severity": 85
    },
    "fox": {
        "name": "FoxAuto",
        "uri_patterns": [r"/foxauto", r"/fx"],
        "mitre": "T1071",
        "severity": 85
    },
    "bear": {
        "name": "BearLog",
        "uri_patterns": [r"/bearlog", r"/br"],
        "mitre": "T1071",
        "severity": 90
    },
    "wolf": {
        "name": "Wolf RAT",
        "uri_patterns": [r"/wolfrat", r"/wolf"],
        "mitre": "T1071",
        "severity": 95
    },
    "lion": {
        "name": "Lion RAT",
        "uri_patterns": [r"/lionrat", r"/lion"],
        "mitre": "T1071",
        "severity": 95
    },
    "tiger": {
        "name": "Tiger RAT",
        "uri_patterns": [r"/tigerrat", r"/tiger"],
        "mitre": "T1071",
        "severity": 95
    },
    "panther": {
        "name": "Panther RAT",
        "uri_patterns": [r"/panther", r"/puma"],
        "mitre": "T1071",
        "severity": 95
    },
    "leopard": {
        "name": "Leopard",
        "uri_patterns": [r"/leopard", r"/leo"],
        "mitre": "T1071",
        "severity": 90
    },
    "cheetah": {
        "name": "Cheetah",
        "uri_patterns": [r"/cheetah", r"/ch"],
        "mitre": "T1071",
        "severity": 90
    },
    "condor": {
        "name": "Condor",
        "uri_patterns": [r"/condor", r"/cn"],
        "mitre": "T1071",
        "severity": 90
    },
    "falcon": {
        "name": "Falcon",
        "uri_patterns": [r"/falcon", r"/fc"],
        "mitre": "T1071",
        "severity": 90
    },
    "phoenix": {
        "name": "Phoenix",
        "uri_patterns": [r"/phoenix", r"/ph"],
        "mitre": "T1071",
        "severity": 85
    },
    "eagle": {
        "name": "Eagle",
        "uri_patterns": [r"/eagle", r"/eg"],
        "mitre": "T1071",
        "severity": 85
    },
    "crow": {
        "name": "Crow RAT",
        "uri_patterns": [r"/crowrat", r"/crow"],
        "mitre": "T1071",
        "severity": 85
    },
    "raven": {
        "name": "Raven",
        "uri_patterns": [r"/raven", r"/ra"],
        "mitre": "T1071",
        "severity": 85
    },
    "crow": {
        "name": "Crow",
        "uri_patterns": [r"/crow", r"/cr"],
        "mitre": "T1071",
        "severity": 85
    },
    "hawk": {
        "name": "Hawk",
        "uri_patterns": [r"/hawk", r"/hw"],
        "mitre": "T1071",
        "severity": 85
    },
    "sparrow": {
        "name": "Sparrow",
        "uri_patterns": [r"/sparrow", r"/sp"],
        "mitre": "T1071",
        "severity": 85
    },
    "night": {
        "name": "Night",
        "uri_patterns": [r"/night", r"/nt"],
        "mitre": "T1071",
        "severity": 95
    },
    "shadow": {
        "name": "Shadow",
        "uri_patterns": [r"/shadow", r"/sh"],
        "mitre": "T1071",
        "severity": 95
    },
    "phantom": {
        "name": "Phantom RAT",
        "uri_patterns": [r"/phantom", r"/ph"],
        "mitre": "T1071",
        "severity": 95
    },
    "phantomv2": {
        "name": "Phantom v2",
        "uri_patterns": [r"/phantomv2", r"/ph2"],
        "mitre": "T1071",
        "severity": 95
    },
    "ghost": {
        "name": "Ghost RAT",
        "uri_patterns": [r"/ghost/panel", r"/ghost/rat", r"/gh"],
        "mitre": "T1071",
        "severity": 95
    },
    "ghostv": {
        "name": "Ghost v1/v2",
        "uri_patterns": [r"/ghostv", r"/ghv"],
        "mitre": "T1071",
        "severity": 95
    },
    "stealth": {
        "name": "Stealth",
        "uri_patterns": [r"/stealth", r"/st"],
        "mitre": "T1071",
        "severity": 95
    },
    "invis": {
        "name": "InvisiRAT",
        "uri_patterns": [r"/invis", r"/inv"],
        "mitre": "T1071",
        "severity": 95
    },
    "hidden": {
        "name": "HiddenRAT",
        "uri_patterns": [r"/hidden", r"/hd"],
        "mitre": "T1071",
        "severity": 95
    },
    "secret": {
        "name": "SecretRAT",
        "uri_patterns": [r"/secret", r"/sec"],
        "mitre": "T1071",
        "severity": 95
    },
    "private": {
        "name": "PrivateRAT",
        "uri_patterns": [r"/private", r"/pr"],
        "mitre": "T1071",
        "severity": 95
    },
    "elite": {
        "name": "EliteRAT",
        "uri_patterns": [r"/elite", r"/el"],
        "mitre": "T1071",
        "severity": 95
    },
    "secure": {
        "name": "SecureRAT",
        "uri_patterns": [r"/secure", r"/sec"],
        "mitre": "T1071",
        "severity": 95
    },
    "platinum": {
        "name": "Platinum",
        "uri_patterns": [r"/platinum", r"/pl"],
        "mitre": "T1071",
        "severity": 95
    },
    "diamond": {
        "name": "Diamond",
        "uri_patterns": [r"/diamond", r"/dm"],
        "mitre": "T1071",
        "severity": 95
    },
    "ruby": {
        "name": "RubyRAT",
        "uri_patterns": [r"/ruby", r"/rb"],
        "mitre": "T1071",
        "severity": 95
    },
    "emerald": {
        "name": "Emerald",
        "uri_patterns": [r"/emerald", r"/em"],
        "mitre": "T1071",
        "severity": 95
    },
    "sapphire": {
        "name": "Sapphire",
        "uri_patterns": [r"/sapphire", r"/sp"],
        "mitre": "T1071",
        "severity": 95
    },
    "onyx": {
        "name": "Onyx",
        "uri_patterns": [r"/onyx", r"/on"],
        "mitre": "T1071",
        "severity": 95
    },
    "obsidian": {
        "name": "Obsidian",
        "uri_patterns": [r"/obsidian", r"/ob"],
        "mitre": "T1071",
        "severity": 95
    },
    "amethyst": {
        "name": "Amethyst",
        "uri_patterns": [r"/amethyst", r"/am"],
        "mitre": "T1071",
        "severity": 95
    },
    "topaz": {
        "name": "Topaz",
        "uri_patterns": [r"/topaz", r"/tp"],
        "mitre": "T1071",
        "severity": 95
    },
    "jade": {
        "name": "Jade",
        "uri_patterns": [r"/jade", r"/jd"],
        "mitre": "T1071",
        "severity": 90
    },
    "garnet": {
        "name": "Garnet",
        "uri_patterns": [r"/garnet", r"/ga"],
        "mitre": "T1071",
        "severity": 90
    },
    "peridot": {
        "name": "Peridot",
        "uri_patterns": [r"/peridot", r"/pr"],
        "mitre": "T1071",
        "severity": 90
    },
    "opal": {
        "name": "Opal",
        "uri_patterns": [r"/opal", r"/op"],
        "mitre": "T1071",
        "severity": 90
    },
    "turquoise": {
        "name": "Turquoise",
        "uri_patterns": [r"/turquoise", r"/tq"],
        "mitre": "T1071",
        "severity": 90
    },
    "aquamarine": {
        "name": "Aquamarine",
        "uri_patterns": [r"/aquamarine", r"/aq"],
        "mitre": "T1071",
        "severity": 90
    },
    # === Banking Trojans ===
    "zeus": {
        "name": "Zeus Botnet",
        "uri_patterns": [r"/zeus", r"/bot", r"/gate"],
        "mitre": "T1071",
        "severity": 100
    },
    "zeuspro": {
        "name": "Zeus Pro",
        "uri_patterns": [r"/zeuspro", r"/zpro"],
        "mitre": "T1071",
        "severity": 95
    },
    "citadel": {
        "name": "Citadel",
        "uri_patterns": [r"/citadel", r"/cit"],
        "mitre": "T1071",
        "severity": 95
    },
    "gozi": {
        "name": "Gozi",
        "uri_patterns": [r"/gozi", r"/isp"],
        "mitre": "T1071",
        "severity": 95
    },
    "pandabanker": {
        "name": "Panda Banker",
        "uri_patterns": [r"/panda", r"/bank"],
        "mitre": "T1071",
        "severity": 90
    },
    "carberp": {
        "name": "Carberp",
        "uri_patterns": [r"/carberp", r"/car"],
        "mitre": "T1071",
        "severity": 95
    },
    "dyre": {
        "name": "Dyre",
        "uri_patterns": [r"/dyre", r"/dy"],
        "mitre": "T1071",
        "severity": 95
    },
    "bugat": {
        "name": "Bugat",
        "uri_patterns": [r"/bugat", r"/bug"],
        "mitre": "T1071",
        "severity": 90
    },
    "cridex": {
        "name": "Cridex",
        "uri_patterns": [r"/cridex", r"/crd"],
        "mitre": "T1071",
        "severity": 90
    },
    "shamans": {
        "name": "Shamans",
        "uri_patterns": [r"/shaman", r"/sha"],
        "mitre": "T1071",
        "severity": 90
    },
    "tinba": {
        "name": "TinyBanker",
        "uri_patterns": [r"/tinba", r"/tin"],
        "mitre": "T1071",
        "severity": 85
    },
    "ATM": {
        "name": "ATM Malware",
        "uri_patterns": [r"/atm", r"/cash"],
        "mitre": "T1071",
        "severity": 95
    },
    # === Droppers ===
    "donbot": {
        "name": "Donbot Dropper",
        "uri_patterns": [r"/donbot", r"/don"],
        "mitre": "T1105",
        "severity": 90
    },
    "gandrops": {
        "name": "GandCrab Dropper",
        "uri_patterns": [r"/gandrop", r"/drop"],
        "mitre": "T1105",
        "severity": 95
    },
    "njdrops": {
        "name": "njRAT Dropper",
        "uri_patterns": [r"/njdrop", r"/dNJ"],
        "mitre": "T1105",
        "severity": 90
    },
    "pricedrop": {
        "name": "Price Dropper",
        "uri_patterns": [r"/pricedrop", r"/prd"],
        "mitre": "T1105",
        "severity": 85
    },
    "zequedrop": {
        "name": "zekDropper",
        "uri_patterns": [r"/zekdrop", r"/zekd"],
        "mitre": "T1105",
        "severity": 90
    },
    # === Worms ===
    "conficker": {
        "name": "Conficker Worm",
        "uri_patterns": [r"/conficker", r"/conf"],
        "mitre": "T1021",
        "severity": 70
    },
    "worm": {
        "name": "Generic Worm",
        "uri_patterns": [r"/worm", r"/spread"],
        "mitre": "T1021",
        "severity": 70
    },
    "virmon": {
        "name": "Virut Worm",
        "uri_patterns": [r"/virut", r"/vir"],
        "mitre": "T1021",
        "severity": 70
    },
    "sasser": {
        "name": "Sasser Worm",
        "uri_patterns": [r"/sasser", r"/sas"],
        "mitre": "T1021",
        "severity": 60
    },
    # === Rootkits ===
    "rootkit": {
        "name": "Rootkit",
        "uri_patterns": [r"/rootkit", r"/hide"],
        "mitre": "T1014",
        "severity": 95
    },
    "hood": {
        "name": "Hood Rootkit",
        "uri_patterns": [r"/hoodroot", r"/hood"],
        "mitre": "T1014",
        "severity": 90
    },
    "azuqui": {
        "name": "Azuquith",
        "uri_patterns": [r"/azuquit", r"/azq"],
        "mitre": "T1014",
        "severity": 90
    },
    # === Keyloggers ===
    "keygrab": {
        "name": "KeyGrabber",
        "uri_patterns": [r"/keygrab", r"/keyg"],
        "mitre": "T1056",
        "severity": 85
    },
    "reflo": {
        "name": "Reflo",
        "uri_patterns": [r"/reflo", r"/ref"],
        "mitre": "T1056",
        "severity": 85
    },
    "clclogger": {
        "name": "ClcLogger",
        "uri_patterns": [r"/clclogger", r"/clc"],
        "mitre": "T1056",
        "severity": 80
    },
    "membV": {
        "name": "Member",
        "uri_patterns": [r"/member", r"/memb"],
        "mitre": "T1056",
        "severity": 80
    },
    # === Backdoors ===
    "bkdoor": {
        "name": "Generic Backdoor",
        "uri_patterns": [r"/backdoor", r"/bdoor"],
        "mitre": "T1071",
        "severity": 90
    },
    "pcntp": {
        "name": "PcNode",
        "uri_patterns": [r"/pcntp", r"/pcnt"],
        "mitre": "T1071",
        "severity": 85
    },
    "cym": {
        "name": "Cymothoa",
        "uri_patterns": [r"/cymothoa", r"/cym"],
        "mitre": "T1071",
        "severity": 85
    },
    "beastdoor": {
        "name": "BeastDoor",
        "uri_patterns": [r"/beastdoor", r"/beast"],
        "mitre": "T1071",
        "severity": 85
    },
    # === Spyware ===
    "spysoft": {
        "name": "Spyware",
        "uri_patterns": [r"/spysoft", r"/spy"],
        "mitre": "T1056",
        "severity": 80
    },
    "flexispy": {
        "name": "FlexiSpy",
        "uri_patterns": [r"/flexispy", r"/flex"],
        "mitre": "T1056",
        "severity": 80
    },
    "mobilespy": {
        "name": "Mobile Spy",
        "uri_patterns": [r"/mobilespy", r"/mob"],
        "mitre": "T1056",
        "severity": 80
    },
    # === Adware ===
    "adware": {
        "name": "Adware",
        "uri_patterns": [r"/adware", r"/ad"],
        "mitre": "T1064",
        "severity": 50
    },
    "genad": {
        "name": "GenAdware",
        "uri_patterns": [r"/genad", r"/gad"],
        "mitre": "T1064",
        "severity": 50
    },
    # === Botnets ===
    "mirai": {
        "name": "Mirai Botnet",
        "uri_patterns": [r"/mirai", r"/bot"],
        "mitre": "T1021",
        "severity": 85
    },
    "mirai_variant": {
        "name": "Mirai Variant",
        "uri_patterns": [r"/mirai2", r"/mr2"],
        "mitre": "T1021",
        "severity": 85
    },
    "qbot": {
        "name": "Qbot",
        "uri_patterns": [r"/qbot", r"/qb"],
        "mitre": "T1021",
        "severity": 85
    },
    "emotetc2": {
        "name": "Emotet C2",
        "uri_patterns": [r"/emotet", r"/payment"],
        "mitre": "T1071",
        "severity": 100
    },
    "icedid_c2": {
        "name": "IcedID C2",
        "uri_patterns": [r"/icedid", r"/verify"],
        "mitre": "T1071",
        "severity": 95
    },
    "trick_c2": {
        "name": "TrickBot C2",
        "uri_patterns": [r"/trickbot", r"/gate"],
        "mitre": "T1071",
        "severity": 95
    },
    "ursnif_c2": {
        "name": "Ursnif C2",
        "uri_patterns": [r"/ursnif", r"/cgi"],
        "mitre": "T1071",
        "severity": 95
    }
}


# =============================================================================
# Clase Attack Detector
# =============================================================================

class AttackDetector:
    """Detector de ataques en trafico de red."""

    def __init__(self, packets: List = None, connections=None, http_requests=None):
        self.packets = packets or []
        self.connections = connections
        self.http_requests = http_requests or []
        self.detected_attacks: List[Attack] = []

    def detect_port_scan(self, threshold: int = 15) -> List[Attack]:
        """Detecta escaneo de puertos."""
        attacks = []
        port_access = defaultdict(lambda: {"ips": set(), "ports": set()})

        for p in self.packets:
            if p.protocol in ("tcp", "udp") and p.dst_port > 0:
                port_access[p.ip_dst]["ips"].add(p.ip_src)
                port_access[p.ip_dst]["ports"].add(p.dst_port)

        for target_ip, data in port_access.items():
            scanned_ports = len(data["ports"])
            if scanned_ports >= threshold:
                unique_attackers = len(data["ips"])
                src_ips = list(data["ips"])[:5]
                ports_list = list(data["ports"])
                
                attack = Attack(
                    attack_type="port_scan",
                    src_ip=src_ips[0] if src_ips else "",
                    dst_ip=target_ip,
                    src_port=ports_list[0] if ports_list else 0,
                    dst_port=ports_list[-1] if ports_list else 0,
                    protocol="TCP",
                    severity="HIGH",
                    risk=35,
                    description=f"Port scan: {scanned_ports} puertos desde {unique_attackers} IP(s)",
                    evidence=[f"Scanned {scanned_ports} ports from {len(data['ips'])} sources"],
                    mitre_technique=MITRE_TECHNIQUES["port_scan"],
                    indicators={
                        "scanned_ports": scanned_ports,
                        "attacker_count": unique_attackers,
                        "threshold": threshold
                    }
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_host_discovery(self, threshold: int = 10) -> List[Attack]:
        """Detecta descubrimiento de hosts (ICMP ping sweep)."""
        attacks = []
        icmp_targets = defaultdict(set)

        for p in self.packets:
            if p.protocol == "icmp" and p.icmp_type == 8:
                icmp_targets[p.ip_src].add(p.ip_dst)

        for src_ip, targets in icmp_targets.items():
            if len(targets) >= threshold:
                attack = Attack(
                    attack_type="host_discovery",
                    src_ip=src_ip,
                    protocol="ICMP",
                    severity="MEDIUM",
                    risk=25,
                    description=f"ICMP ping sweep: {len(targets)} hosts",
                    evidence=[f"ICMP echo requests to {len(targets)} targets"],
                    mitre_technique="T1046",
                    indicators={"targets": len(targets)}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_syn_flood(self, threshold: int = 50, window_seconds: float = 60.0) -> List[Attack]:
        """Detecta inundacion SYN (DoS)."""
        attacks = []
        syn_packets = defaultdict(list)

        for p in self.packets:
            if p.protocol == "tcp":
                flags = p.tcp_flags
                if flags & 0x02 and not (flags & 0x10):
                    syn_packets[p.ip_src].append(p.timestamp)

        for src_ip, timestamps in syn_packets.items():
            recent_syn = [ts for ts in timestamps if ts >= max(timestamps) - window_seconds]
            if len(recent_syn) >= threshold:
                time_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

                attack = Attack(
                    attack_type="syn_flood",
                    src_ip=src_ip,
                    protocol="TCP",
                    severity="CRITICAL",
                    risk=70,
                    description=f"SYN flood: {len(recent_syn)} SYN en {window_seconds}s",
                    evidence=[f"{len(recent_syn)} SYN packets without ACK"],
                    mitre_technique=MITRE_TECHNIQUES["syn_flood"],
                    indicators={"syn_count": len(recent_syn), "window": window_seconds}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_icmp_flood(self, threshold: int = 100) -> List[Attack]:
        """Detecta inundacion ICMP (ping flood)."""
        attacks = []
        icmp_counts = defaultdict(int)

        for p in self.packets:
            if p.protocol == "icmp" and p.icmp_type in (8, 0):
                icmp_counts[p.ip_src] += 1

        for src_ip, count in icmp_counts.items():
            if count >= threshold:
                attack = Attack(
                    attack_type="icmp_flood",
                    src_ip=src_ip,
                    protocol="ICMP",
                    severity="HIGH",
                    risk=55,
                    description=f"ICMP flood: {count} paquetes",
                    evidence=[f"{count} ICMP packets"],
                    mitre_technique="T1498",
                    indicators={"packet_count": count}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_udp_flood(self, threshold: int = 100) -> List[Attack]:
        """Detecta inundacion UDP."""
        attacks = []
        udp_counts = defaultdict(int)

        for p in self.packets:
            if p.protocol == "udp":
                udp_counts[p.ip_src] += 1

        for src_ip, count in udp_counts.items():
            if count >= threshold:
                attack = Attack(
                    attack_type="udp_flood",
                    src_ip=src_ip,
                    protocol="UDP",
                    severity="HIGH",
                    risk=40,
                    description=f"UDP flood: {count} datagramas",
                    evidence=[f"{count} UDP packets"],
                    mitre_technique="T1498",
                    indicators={"packet_count": count}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_ssh_brute_force(self, threshold: int = 5, port: int = 22) -> List[Attack]:
        """Detecta fuerza bruta SSH."""
        attacks = []
        ssh_attempts = defaultdict(list)

        for p in self.packets:
            if p.protocol == "tcp" and p.dst_port == port:
                ssh_attempts[p.ip_src].append(p.timestamp)

        for src_ip, timestamps in ssh_attempts.items():
            if len(timestamps) >= threshold:
                attack = Attack(
                    attack_type="ssh_brute_force",
                    src_ip=src_ip,
                    dst_ip="",
                    dst_port=port,
                    protocol="TCP",
                    severity="HIGH",
                    risk=45,
                    description=f"SSH brute force: {len(timestamps)} intentos",
                    evidence=[f"{len(timestamps)} connection attempts to port {port}"],
                    mitre_technique=MITRE_TECHNIQUES["brute_force"],
                    indicators={"attempts": len(timestamps), "port": port}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_ftp_brute_force(self, threshold: int = 5) -> List[Attack]:
        """Detecta fuerza bruta FTP."""
        attacks = []
        ftp_attempts = defaultdict(list)
        
        for p in self.packets:
            if p.protocol == "tcp" and p.dst_port == 21:
                ftp_attempts[p.ip_src].append(p.timestamp)
        
        for src_ip, timestamps in ftp_attempts.items():
            if len(timestamps) >= threshold:
                attack = Attack(
                    attack_type="ftp_brute_force",
                    src_ip=src_ip,
                    dst_ip="",
                    dst_port=21,
                    protocol="TCP",
                    severity="HIGH",
                    risk=45,
                    description=f"FTP brute force: {len(timestamps)} intentos",
                    evidence=[f"{len(timestamps)} connection attempts to port 21"],
                    mitre_technique=MITRE_TECHNIQUES["brute_force"],
                    indicators={"attempts": len(timestamps), "port": 21}
                )
                attacks.append(attack)
        
        self.detected_attacks.extend(attacks)
        return attacks

    def detect_http_brute_force(self, threshold: int = 10) -> List[Attack]:
        """Detecta fuerza bruta HTTP."""
        attacks = []
        http_counts = defaultdict(int)

        for p in self.packets:
            if p.protocol == "tcp" and p.dst_port in (80, 443, 8080, 8443):
                http_counts[p.ip_src] += 1

        for src_ip, count in http_counts.items():
            if count >= threshold:
                ports = [p.dst_port for p in self.packets if p.protocol == "tcp" and p.ip_src == src_ip and p.dst_port in (80, 443, 8080, 8443)]
                protocol = "HTTPS" if 443 in ports else "HTTP"
                attack = Attack(
                    attack_type="http_brute_force",
                    src_ip=src_ip,
                    dst_port=ports[0] if ports else 80,
                    protocol=protocol,
                    severity="HIGH",
                    risk=45,
                    description=f"HTTP brute force: {count} requests",
                    evidence=[f"{count} HTTP requests"],
                    mitre_technique=MITRE_TECHNIQUES["brute_force"],
                    indicators={"requests": count}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_arp_spoofing(self) -> List[Attack]:
        """Detecta envenenamiento ARP (ARP spoofing)."""
        attacks = []
        arp_responses = defaultdict(set)

        for p in self.packets:
            if p.protocol == "arp":
                arp_responses[p.ip_src].add(p.eth_src)

        for ip, macs in arp_responses.items():
            if len(macs) > 1:
                attack = Attack(
                    attack_type="arp_spoofing",
                    src_ip=ip,
                    severity="HIGH",
                    risk=60,
                    description=f"ARP spoofing: IP {ip} con {len(macs)} MACs",
                    evidence=[f"Multiple MACs for IP {ip}: {macs}"],
                    mitre_technique=MITRE_TECHNIQUES["arp_spoofing"],
                    indicators={"mac_count": len(macs), "macs": list(macs)}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_dns_poisoning(self, threshold: int = 3) -> List[Attack]:
        """Detecta envenenamiento DNS."""
        attacks = []
        dns_answers = defaultdict(lambda: {"queries": set(), "answers": set()})

        if hasattr(self, 'dns_queries'):
            for dns in self.dns_queries:
                if dns.answers:
                    for ans in dns.answers[:5]:
                        dns_answers[dns.query]["queries"].add(dns.src_ip)
                        dns_answers[dns.query]["answers"].add(ans)

        for query, data in dns_answers.items():
            if len(data["answers"]) >= threshold:
                attack = Attack(
                    attack_type="dns_poisoning",
                    src_ip=list(data["queries"])[0] if data["queries"] else "",
                    severity="CRITICAL",
                    risk=75,
                    description=f"DNS poisoning: {len(data['answers'])} respostas diferentes para {query}",
                    evidence=[f"Multiple DNS answers for {query}"],
                    mitre_technique=MITRE_TECHNIQUES["dns_poisoning"],
                    indicators={"answers": list(data["answers"])}
                )
                attacks.append(attack)

        return attacks

    def detect_ssl_strip(self) -> List[Attack]:
        """Detecta downgrade SSL."""
        attacks = []

        if hasattr(self, 'connections'):
            ssl_transitions = defaultdict(int)

            for conn in self.connections:
                if hasattr(conn, 'service') and 'ssl' not in conn.service.lower():
                    ssl_transitions[conn.resp_ip] += 1

            for ip, count in ssl_transitions.items():
                if count > 10:
                    attack = Attack(
                        attack_type="ssl_strip",
                        severity="MEDIUM",
                        risk=30,
                        description=f"SSL strip: posibles downgrades",
                        evidence=[f"{count} non-SSL connections after SSL"],
                        mitre_technique="T1567",
                        indicators={"downgrades": count}
                    )
                    attacks.append(attack)

        return attacks

    def detect_data_exfiltration(self, threshold_bytes: int = 10000000) -> List[Attack]:
        """Detecta exfiltracion de datos."""
        attacks = []
        data_transfer = defaultdict(int)

        for p in self.packets:
            data_transfer[p.ip_src] += p.captured_length

        for src_ip, bytes_sent in data_transfer.items():
            if bytes_sent >= threshold_bytes:
                attack = Attack(
                    attack_type="data_exfiltration",
                    src_ip=src_ip,
                    severity="HIGH",
                    risk=55,
                    description=f"Data exfiltration: {bytes_sent} bytes transferidos",
                    evidence=[f"Large data transfer: {bytes_sent} bytes"],
                    mitre_technique=MITRE_TECHNIQUES["data_exfiltration"],
                    indicators={"bytes": bytes_sent, "threshold": threshold_bytes}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_c2_traffic(self, port: int = 4444) -> List[Attack]:
        """Detecta comunicacion C2."""
        attacks = []
        outbound_to_common_ports = defaultdict(int)

        for p in self.packets:
            if p.dst_port == port:
                outbound_to_common_ports[p.ip_src] += 1

        for src_ip, count in outbound_to_common_ports.items():
            if count > 0:
                attack = Attack(
                    attack_type="c2_traffic",
                    src_ip=src_ip,
                    dst_port=port,
                    severity="CRITICAL",
                    risk=80,
                    description=f"Posible C2: conexiones al puerto {port}",
                    evidence=[f"{count} connections to known C2 port {port}"],
                    mitre_technique=MITRE_TECHNIQUES["c2"],
                    indicators={"port": port, "connections": count}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_dns_tunneling(self, query_threshold: int = 50, length_threshold: int = 100) -> List[Attack]:
        """Detecta tunneling DNS."""
        attacks = []

        if hasattr(self, 'dns_queries'):
            dns_stats = defaultdict(lambda: {"count": 0, "total_length": 0})

            for dns in self.dns_queries:
                dns_stats[dns.src_ip]["count"] += 1
                dns_stats[dns.src_ip]["total_length"] += len(dns.query)

            for src_ip, stats in dns_stats.items():
                if stats["count"] >= query_threshold or stats["total_length"] >= length_threshold:
                    attack = Attack(
                        attack_type="dns_tunneling",
                        src_ip=src_ip,
                        severity="HIGH",
                        risk=60,
                        description=f"DNS tunneling: {stats['count']} queries, {stats['total_length']} bytes",
                        evidence=[f"Abnormal DNS query pattern"],
                        mitre_technique="T1071",
                        indicators={
                            "query_count": stats["count"],
                            "total_length": stats["total_length"]
                        }
                    )
                    attacks.append(attack)

        return attacks

    SUSPICIOUS_EXTENSIONS = [
        ".exe", ".dll", ".rar", ".zip", ".js", ".vbs", ".bat", ".ps1",
        ".scr", ".pif", ".application", ".gadget", ".msi", ".msp",
        ".com", ".hta", ".cpl", ".ocx", ".nsh"
    ]

    SUSPICIOUS_PATHS = [
        r"/download", r"/update", r"/install", r"/client",
        r"/vnc", r"/gr", r"/rat", r"/stealer", r"/loader",
        r"/panel", r"/c2", r"/checkin", r"/gate", r"/stub",
        r"/firmware", r"/plugin", r"/module", r"/payload"
    ]

    SUSPICIOUS_DOMAINS_PATTERNS = [
        r"download.*\.com", r"update.*\.net", r"free.*\.xyz",
        r"crack", r"keygen", r"serial", r"license",
        r"modandcracked", r"fake.*\.com"
    ]

    def detect_suspicious_downloads(self) -> List[Attack]:
        """Detecta descargas sospechosas - con detalles."""
        attacks = []
        http_downloads = defaultdict(lambda: {"count": 0, "extensions": set(), "ports": set(), "src_ips": set()})

        for p in self.packets:
            if p.dst_port in (80, 443) and p.ip_dst and p.ip_src:
                key = f"{p.ip_dst}"
                http_downloads[key]["count"] += 1
                http_downloads[key]["ports"].add(p.dst_port)
                http_downloads[key]["src_ips"].add(p.ip_src)

        for ip, data in http_downloads.items():
            if data["count"] >= 5:
                ports_list = list(data["ports"])
                protocol = "HTTPS" if 443 in ports_list else "HTTP" if 80 in ports_list else "TCP"
                attack = Attack(
                    attack_type="suspicious_download",
                    src_ip=next(iter(data["src_ips"])),
                    dst_ip=ip,
                    src_port=ports_list[0] if ports_list else 80,
                    dst_port=80,
                    protocol=protocol,
                    severity="HIGH",
                    risk=75,
                    description=f"Malware download: {data['count']} suspicious requests to external host",
                    evidence=[
                        f"{data['count']} requests",
                        f"Src: {next(iter(data['src_ips']))}",
                        f"Ports: {sorted(data['ports'])}"
                    ],
                    mitre_technique=MITRE_TECHNIQUES["malware_download"],
                    indicators={
                        "download_count": data["count"],
                        "external_ip": ip,
                        "source_ports": list(data["ports"]),
                        "all_sources": list(data["src_ips"])[:5]
                    }
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_c2_behavior(self) -> List[Attack]:
        """Detecta comportamiento C2 - con detalles."""
        attacks = []
        dest_stats = defaultdict(lambda: {"count": 0, "ports": set(), "src_ips": set()})

        for p in self.packets:
            if not p.ip_dst.startswith("10.") and not p.ip_dst.startswith("192.168."):
                key = p.ip_dst
                dest_stats[key]["count"] += 1
                dest_stats[key]["ports"].add(p.dst_port)
                dest_stats[key]["src_ips"].add(p.ip_src)

        for ip, stats in dest_stats.items():
            if stats["count"] >= 30:
                unusual_ports = [pt for pt in stats["ports"] if pt not in (80, 443, 53)]
                ports_list = list(stats["ports"])
                protocol = "HTTPS" if 443 in ports_list else "HTTP" if 80 in ports_list else "TCP"
                if unusual_ports or stats["count"] >= 50:
                    attack = Attack(
                        attack_type="possible_c2",
                        src_ip=next(iter(stats["src_ips"])),
                        dst_ip=ip,
                        src_port=ports_list[0] if ports_list else 4444,
                        dst_port=ports_list[0] if ports_list else 4444,
                        protocol=protocol,
                        severity="CRITICAL",
                        risk=90,
                        description=f"C2 activity: {stats['count']} connections to {ip}, unusual ports detected",
                        evidence=[
                            f"{stats['count']} total connections",
                            f"Unusual ports: {unusual_ports}",
                            f"Source: {next(iter(stats['src_ips']))}"
                        ],
                        mitre_technique=MITRE_TECHNIQUES["c2"],
                        indicators={
                            "external_ip": ip,
                            "connection_count": stats["count"],
                            "ports": list(stats["ports"]),
                            "unusual_ports": unusual_ports,
                            "possible_beacon": True
                        }
                    )
                    attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_data_exfiltration(self) -> List[Attack]:
        """Detecta exfiltracion por transferencias grandes."""
        attacks = []
        transfer_stats = defaultdict(lambda: {"bytes": 0, "dst_ips": set()})

        for p in self.packets:
            if not p.ip_dst.startswith("10.") and not p.ip_dst.startswith("192.168."):
                transfer_stats[p.ip_dst]["bytes"] += p.captured_length
                transfer_stats[p.ip_dst]["dst_ips"].add(p.ip_src)

        threshold = 10_000_000
        for ip, stats in transfer_stats.items():
            if stats["bytes"] >= threshold:
                attack = Attack(
                    attack_type="data_exfiltration",
                    src_ip=next(iter(stats["dst_ips"])),
                    dst_ip=ip,
                    severity="HIGH",
                    risk=70,
                    description=f"Large data transfer: {stats['bytes']/1024/1024:.1f}MB",
                    evidence=[f"Transferred {stats['bytes']/1024/1024:.1f}MB to external IP"],
                    mitre_technique=MITRE_TECHNIQUES["data_exfiltration"],
                    indicators={"bytes": stats["bytes"]}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_network_anomaly(self) -> List[Attack]:
        """Detecta anomalias de red - umbral ajustado."""
        attacks = []
        connections_per_dest = defaultdict(lambda: {"count": 0, "src_ips": set()})

        for p in self.packets:
            if not p.ip_dst.startswith("10.") and not p.ip_dst.startswith("192.168."):
                connections_per_dest[p.ip_dst]["count"] += 1
                connections_per_dest[p.ip_dst]["src_ips"].add(p.ip_src)

        for ip, data in connections_per_dest.items():
            if data["count"] > 200:
                attack = Attack(
                    attack_type="network_anomaly",
                    src_ip=next(iter(data["src_ips"])),
                    dst_ip=ip,
                    severity="MEDIUM",
                    risk=40,
                    description=f"High connection count to {ip}: {data['count']} connections",
                    evidence=[f"{data['count']} connections from internal host"],
                    indicators={"connections": data["count"]}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_mac_spoofing(self) -> List[Attack]:
        """Detecta MAC spoofing - misma IP con diferentes MACs."""
        attacks = []
        ip_mac_map = defaultdict(set)

        for p in self.packets:
            if hasattr(p, 'src_mac') and p.src_mac:
                ip_mac_map[p.ip_src].add(p.src_mac)

        for ip, macs in ip_mac_map.items():
            if len(macs) > 1:
                attack = Attack(
                    attack_type="mac_spoofing",
                    src_ip=ip,
                    severity="HIGH",
                    risk=70,
                    description=f"MAC spoofing detected: IP {ip} with {len(macs)} different MACs",
                    evidence=[f"MACs: {macs}"],
                    mitre_technique="T1554",
                    indicators={"mac_addresses": list(macs)}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_tcp_hijacking(self) -> List[Attack]:
        """Detecta posible TCP hijacking - secuencia anomalias."""
        attacks = []
        tcp_anomalies = defaultdict(lambda: {"resets": 0, "out_of_order": 0})

        for p in self.packets:
            if hasattr(p, 'flags') and p.flags:
                flags = str(p.flags).upper()
                if 'RST' in flags or 'R' in flags:
                    key = p.ip_dst
                    tcp_anomalies[key]["resets"] += 1

        for ip, stats in tcp_anomalies.items():
            if stats["resets"] > 10:
                attack = Attack(
                    attack_type="tcp_hijacking",
                    src_ip=ip,
                    severity="HIGH",
                    risk=75,
                    description=f"TCP hijacking attempt: {stats['resets']} RST packets to {ip}",
                    evidence=[f"RST packets: {stats['resets']}"],
                    mitre_technique="T1574",
                    indicators={"rst_packets": stats["resets"]}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_web_attacks(self) -> List[Attack]:
        """Detecta ataques web: SQL injection, XSS, etc."""
        attacks = []
        sql_patterns = r"(union.*select|or\s+1=1|'|\";|--|xp_)"
        xss_patterns = r"(<script|javascript:|alert\(|onerror=|onload=)"
        cmd_patterns = r"((\|\||\;|\&|\$|\`))"

        uri_hits = defaultdict(lambda: {"count": 0, "type": set()})

        for p in self.packets:
            if p.dst_port in (80, 443) and p.raw_data:
                payload = p.raw_data.decode('utf-8', errors='ignore') if isinstance(p.raw_data, bytes) else str(p.raw_data)
                if re.search(sql_patterns, payload, re.I):
                    uri_hits[p.ip_dst]["count"] += 1
                    uri_hits[p.ip_dst]["type"].add("sql_injection")
                if re.search(xss_patterns, payload, re.I):
                    uri_hits[p.ip_dst]["count"] += 1
                    uri_hits[p.ip_dst]["type"].add("xss")

        for ip, data in uri_hits.items():
            if data["count"] > 0:
                attack = Attack(
                    attack_type="web_attack",
                    src_ip=ip,
                    severity="CRITICAL",
                    risk=85,
                    description=f"Web attack detected: {data['type']}",
                    evidence=[f"Attack types: {data['type']}, count: {data['count']}"],
                    mitre_technique="T1190",
                    indicators={"attack_types": list(data["type"])}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_dns_spoofing(self) -> List[Attack]:
        """Detecta posible DNS spoofing/poisoning."""
        attacks = []
        dns_responses = defaultdict(lambda: {"count": 0, "answers": set()})

        for p in self.packets:
            if p.dst_port == 53 and hasattr(p, 'dns_answer'):
                dns_responses[p.ip_dst]["count"] += 1
                if p.dns_answer:
                    dns_responses[p.ip_dst]["answers"].add(str(p.dns_answer))

        for ip, stats in dns_responses.items():
            if len(stats["answers"]) > 5:
                attack = Attack(
                    attack_type="dns_spoofing",
                    src_ip=ip,
                    severity="HIGH",
                    risk=80,
                    description=f"DNS spoofing: multiple answers to same query",
                    evidence=[f"Answers: {stats['answers']}"],
                    mitre_technique="T1651",
                    indicators={"answer_count": stats["count"]}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_enumeration(self) -> List[Attack]:
        """Detecta enumeracion de red: samba, snmp,ldap, etc."""
        attacks = []
        enum_ports = {137: "netbios", 138: "netbios", 139: "smb", 161: "snmp", 389: "ldap"}

        enum_hits = defaultdict(lambda: {"count": 0, "types": set()})

        for p in self.packets:
            port = p.dst_port
            if port in enum_ports:
                key = p.ip_dst
                enum_hits[key]["count"] += 1
                enum_hits[key]["types"].add(enum_ports[port])

        for ip, data in enum_hits.items():
            if data["count"] > 5:
                attack = Attack(
                    attack_type="network_enumeration",
                    src_ip=ip,
                    severity="MEDIUM",
                    risk=25,
                    description=f"Network enumeration: {data['types']}",
                    evidence=[f"Types: {data['types']}, count: {data['count']}"],
                    mitre_technique="T1082",
                    indicators={"enum_types": list(data["types"])}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_dos_attacks(self) -> List[Attack]:
        """Detecta ataques DoS: Smurf, Teardrop, Ping of Death, etc."""
        attacks = []

        icmp_flood = defaultdict(int)
        syn_flood = defaultdict(int)
        udp_flood = defaultdict(int)
        fragmented = defaultdict(int)
        ping_large = defaultdict(int)

        for p in self.packets:
            if p.protocol == "icmp":
                if hasattr(p, 'length') and p.length > 1000:
                    ping_large[p.ip_src] += 1
                else:
                    icmp_flood[p.ip_src] += 1

            if p.protocol == "tcp" and hasattr(p, 'flags'):
                if 'S' in str(p.flags) and not 'A' in str(p.flags):
                    syn_flood[p.ip_src] += 1

            if p.protocol == "udp":
                udp_flood[p.ip_src] += 1

            if hasattr(p, 'frag_offset') and p.frag_offset > 0:
                fragmented[p.ip_src] += 1

        for ip, count in icmp_flood.items():
            if count > 50:
                attack = Attack(
                    attack_type="icmp_flood",
                    src_ip=ip,
                    protocol="ICMP",
                    severity="CRITICAL",
                    risk=90,
                    description=f"ICMP Flood (Smurf variant): {count} packets",
                    evidence=[f"ICMP count: {count}"],
                    mitre_technique="T1498",
                    indicators={"packet_count": count, "type": "smurf"}
                )
                attacks.append(attack)

        for ip, count in syn_flood.items():
            if count > 100:
                attack = Attack(
                    attack_type="syn_flood",
                    src_ip=ip,
                    protocol="TCP",
                    severity="CRITICAL",
                    risk=90,
                    description=f"SYN Flood (DoS): {count} packets",
                    evidence=[f"SYN count: {count}"],
                    mitre_technique="T1498",
                    indicators={"packet_count": count, "type": "syn_flood"}
                )
                attacks.append(attack)

        for ip, count in udp_flood.items():
            if count > 100:
                attack = Attack(
                    attack_type="udp_flood",
                    src_ip=ip,
                    protocol="UDP",
                    severity="HIGH",
                    risk=80,
                    description=f"UDP Flood/DoS: {count} packets",
                    evidence=[f"UDP count: {count}"],
                    mitre_technique="T1498",
                    indicators={"packet_count": count}
                )
                attacks.append(attack)

        for ip, count in ping_large.items():
            if count > 10:
                attack = Attack(
                    attack_type="ping_of_death",
                    src_ip=ip,
                    severity="HIGH",
                    risk=85,
                    description=f"Ping of Death: {count} large ICMP packets",
                    evidence=[f"Large ICMP: {count}"],
                    mitre_technique="T1498",
                    indicators={"packet_count": count, "type": "ping_of_death"}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_cryptojacking(self) -> List[Attack]:
        """Detecta cryptojacking - tráfico a pools de crypto mining."""
        attacks = []
        crypto_patterns = [
            "mine", "cryptonight", "cryptonight", "stratum", "coinhive",
            "jsecoin", "coinhive", "cryptoloot", "miner", "hashrate"
        ]
        crypto_ips = defaultdict(int)

        for p in self.packets:
            if p.dst_port in (80, 443, 3333, 5555, 7777, 8888, 14444) and p.raw_data:
                payload = str(p.raw_data).lower() if p.raw_data else ""
                for pattern in crypto_patterns:
                    if pattern in payload:
                        crypto_ips[p.ip_dst] += 1

        for ip, count in crypto_ips.items():
            if count > 0:
                attack = Attack(
                    attack_type="cryptojacking",
                    src_ip=ip,
                    severity="CRITICAL",
                    risk=95,
                    description=f"Cryptojacking: conexiones a pool crypto mining",
                    evidence=[f"Hits: {count}"],
                    mitre_technique="T1496",
                    indicators={"connection_count": count}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_cleartext_credentials(self) -> List[Attack]:
        """Detecta credenciales en claro - FTP, Telnet, HTTP basic auth."""
        attacks = []
        cleartext_patterns = [b"Authorization: Basic", b"user=", b"passwd=", b"password="]
        protocols = {21: "ftp", 23: "telnet", 80: "http"}

        creds_transmitted = defaultdict(lambda: {"count": 0, "protocol": set()})

        for p in self.packets:
            port = p.dst_port
            if port in protocols:
                payload = p.raw_data if p.raw_data else b""
                for pattern in cleartext_patterns:
                    if pattern in payload:
                        key = p.ip_src
                        creds_transmitted[key]["count"] += 1
                        creds_transmitted[key]["protocol"].add(protocols[port])

        for ip, data in creds_transmitted.items():
            if data["count"] > 0:
                attack = Attack(
                    attack_type="cleartext_credentials",
                    src_ip=ip,
                    severity="HIGH",
                    risk=80,
                    description=f"Credenciales en claro transmitidas: {data['protocol']}",
                    evidence=[f"Protocols: {data['protocol']}, count: {data['count']}"],
                    mitre_technique="T1072",
                    indicators={"protocols": list(data["protocol"])}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_ddos(self) -> List[Attack]:
        """Detecta DDoS - ataques distribuidos desde múltiples fuentes."""
        attacks = []
        targets = defaultdict(lambda: {"count": 0, "attackers": set()})

        for p in self.packets:
            if not p.ip_dst.startswith("10."):
                key = p.ip_dst
                targets[key]["count"] += 1
                targets[key]["attackers"].add(p.ip_src)

        for ip, data in targets.items():
            attacker_count = len(data["attackers"])
            if attacker_count > 5 and data["count"] > 100:
                attack = Attack(
                    attack_type="ddos",
                    src_ip="multiple_sources",
                    dst_ip=ip,
                    severity="CRITICAL",
                    risk=100,
                    description=f"DDoS detectado: {attacker_count} attacking {ip}",
                    evidence=[f"Attackers: {attacker_count}, Packets: {data['count']}"],
                    mitre_technique="T1468",
                    indicators={"attacker_count": attacker_count, "target": ip}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_api_abuse(self) -> List[Attack]:
        """Detecta abuso de APIs y weak crypto."""
        attacks = []
        weak_crypto = {21: "ftp", 23: "telnet", 25: "smtp", 80: "http"}
        api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]

        weak_crypto_usage = defaultdict(lambda: {"count": 0, "type": set()})
        api_abuse = defaultdict(lambda: {"count": 0})

        for p in self.packets:
            port = p.dst_port
            if port in weak_crypto:
                weak_crypto_usage[p.ip_src]["count"] += 1
                weak_crypto_usage[p.ip_src]["type"].add(weak_crypto[port])

            if port in (80, 443) and p.raw_data:
                payload = str(p.raw_data)
                for api in api_patterns:
                    if api in payload:
                        api_abuse[p.ip_src] += 1

        for ip, data in weak_crypto_usage.items():
            if data["count"] > 10:
                attack = Attack(
                    attack_type="weak_crypto",
                    src_ip=ip,
                    severity="MEDIUM",
                    risk=30,
                    description=f"Protocolos inseguros: {data['type']}",
                    evidence=[f"Types: {data['type']}"],
                    mitre_technique="T1040",
                    indicators={"weak_protocols": list(data["type"])}
                )
                attacks.append(attack)

        for ip, count in api_abuse.items():
            if count > 20:
                attack = Attack(
                    attack_type="api_abuse",
                    src_ip=ip,
                    severity="HIGH",
                    risk=70,
                    description=f"API abuse: {count} requests",
                    evidence=[f"API requests: {count}"],
                    mitre_technique="T1059",
                    indicators={"request_count": count}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_all(self) -> List[Attack]:
        """Ejecuta todas las detecciones - analisis comportamental."""
        self.detected_attacks = []

        self.detected_attacks.extend(self.detect_port_scan())
        self.detected_attacks.extend(self.detect_host_discovery())
        self.detected_attacks.extend(self.detect_syn_flood())
        self.detected_attacks.extend(self.detect_icmp_flood())
        self.detected_attacks.extend(self.detect_udp_flood())
        self.detected_attacks.extend(self.detect_ssh_brute_force())
        self.detected_attacks.extend(self.detect_arp_spoofing())
        self.detected_attacks.extend(self.detect_dns_tunneling())

        self.detected_attacks.extend(self.detect_suspicious_downloads())
        self.detected_attacks.extend(self.detect_c2_behavior())
        self.detected_attacks.extend(self.detect_data_exfiltration())
        self.detected_attacks.extend(self.detect_network_anomaly())
        self.detected_attacks.extend(self.detect_mac_spoofing())
        self.detected_attacks.extend(self.detect_tcp_hijacking())
        self.detected_attacks.extend(self.detect_web_attacks())
        self.detected_attacks.extend(self.detect_dns_spoofing())
        self.detected_attacks.extend(self.detect_enumeration())
        self.detected_attacks.extend(self.detect_dos_attacks())
        self.detected_attacks.extend(self.detect_cryptojacking())
        self.detected_attacks.extend(self.detect_cleartext_credentials())
        self.detected_attacks.extend(self.detect_ddos())
        self.detected_attacks.extend(self.detect_api_abuse())

        logger.info(f"Total ataques detectados: {len(self.detected_attacks)}")
        return self.detected_attacks

    def get_attacks_by_severity(self) -> Dict[str, List[Attack]]:
        """Agrupa ataques por severidad."""
        result = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

        for attack in self.detected_attacks:
            if attack.severity in result:
                result[attack.severity].append(attack)

        return result

    def get_summary(self) -> Dict:
        """Obtiene resumen de detecciones."""
        by_severity = self.get_attacks_by_severity()
        by_type = defaultdict(int)

        for attack in self.detected_attacks:
            by_type[attack.attack_type] += 1

        return {
            "total_attacks": len(self.detected_attacks),
            "critical": len(by_severity["CRITICAL"]),
            "high": len(by_severity["HIGH"]),
            "medium": len(by_severity["MEDIUM"]),
            "low": len(by_severity["LOW"]),
            "by_type": dict(by_type)
        }

    def detect_malware_iocs(self) -> List[Attack]:
        """Detecta malware por patrones URI (sin IPs hardcodeadas)."""
        attacks = []
        malware_detected = defaultdict(lambda: {"count": 0, "uris": set(), "src_ips": set()})

        for req in self.http_requests:
            uri = (req.uri or "").lower()
            for malware_name, config in MALWARE_URI_PATTERNS.items():
                for pattern in config.get("uri_patterns", []):
                    if re.search(pattern, uri, re.I):
                        malware_detected[malware_name]["count"] += 1
                        malware_detected[malware_name]["uris"].add(uri)
                        malware_detected[malware_name]["src_ips"].add(req.src_ip)
                        malware_detected[malware_name]["dst_ip"] = req.dst_ip
                        malware_detected[malware_name]["dst_port"] = req.dst_port

        for malware_name, data in malware_detected.items():
            if data["count"] >= 1:
                config = MALWARE_URI_PATTERNS.get(malware_name, {})
                severity = "CRITICAL" if config.get("severity", 90) >= 90 else "HIGH"
                risk = config.get("severity", 90)
                mitre = config.get("mitre", "T1071")
                src_ip = next(iter(data["src_ips"]), "")
                if src_ip.startswith(("10.", "192.168.", "172.")):
                    src_ip = data.get("dst_ip", "")
                attack = Attack(
                    attack_type=f"malware_{malware_name}",
                    src_ip=src_ip,
                    dst_ip=data.get("dst_ip", ""),
                    dst_port=data.get("dst_port", 80),
                    severity=severity,
                    risk=risk,
                    description=f"Possible {config.get('name', malware_name)} C2 traffic",
                    evidence=[f"URI patterns matched: {', '.join(list(data['uris'])[:3])}"],
                    mitre_technique=mitre,
                    indicators={
                        "malware_type": config.get("name", malware_name),
                        "mitre": mitre,
                        "uri_matches": data["count"],
                        "detected_uris": list(data["uris"])[:5]
                    }
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks

    def detect_malware_downloads(self) -> List[Attack]:
        """Detecta descargas de malware por patrones sospechosos (alta confianza)."""
        attacks = []
        download_sites = defaultdict(lambda: {"count": 0, "src_ips": set()})

        for p in self.packets:
            if p.dst_port == 80 and p.dst_port > 0:
                if p.ip_dst and p.ip_dst != "10.0.0.0/8" and not p.ip_dst.startswith("10."):
                    download_sites[p.ip_dst]["count"] += 1
                    download_sites[p.ip_dst]["src_ips"].add(p.ip_src)

        for ip, data in download_sites.items():
            if data["count"] >= 10:
                attack = Attack(
                    attack_type="malware_download",
                    src_ip=next(iter(data["src_ips"])),
                    dst_ip=ip,
                    dst_port=80,
                    severity="HIGH",
                    risk=75,
                    description=f"Suspicious download activity: {data['count']} requests",
                    evidence=[f"Multiple downloads from {ip}"],
                    mitre_technique=MITRE_TECHNIQUES.get("malware_download", "T1105"),
                    indicators={"endpoint": ip, "request_count": data["count"]}
                )
                attacks.append(attack)

        self.detected_attacks.extend(attacks)
        return attacks