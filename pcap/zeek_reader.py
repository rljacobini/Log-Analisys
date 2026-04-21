# =============================================================================
# Zeek Reader - Lectura de logs Zeek
# =============================================================================
#
# Este modulo lee y parsea logs de Zeek (anteriormente Bro IDS).
# Soporta los formatos JSON y ASCII tab-separated.
#
# Logs soportados:
#   - conn.log    - Conexiones de red
#   - http.log   - Peticiones HTTP
#   - dns.log   - Consultas DNS
#   - ssl.log   - Negociaciones SSL/TLS
#   - ssh.log  - Conexiones SSH
#   - ftp.log  - Transferencias FTP
#   - notice.log - Alertas
#
# Uso:
#   from pcap.zeek_reader import ZeekReader
#
#   reader = ZeekReader()
#   reader.read_conn_log("conn.log")
#   reader.read_http_log("http.log")
#   reader.correlate_events()
#
# =============================================================================

import json
import os
import logging
import re
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


# =============================================================================
# Estructuras de Datos
# =============================================================================

@dataclass
class Connection:
    """Conexion de red."""
    uid: str
    orig_ip: str
    orig_port: int
    resp_ip: str
    resp_port: int
    proto: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    local_orig: bool = False
    local_resp: bool = False
    missed_bytes: int = 0
    gap_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_ip_bytes: int = 0
    resp_ip_bytes: int = 0
    ts: str = ""
    service: str = ""


@dataclass
class HTTPRequest:
    """Peticion HTTP."""
    uid: str
    id: str
    ts: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    method: str
    host: str
    uri: str
    referrer: str = ""
    user_agent: str = ""
    status_code: int = 0
    status_msg: str = ""
    response_body_len: int = 0
    mime_type: str = ""


@dataclass
class DNSQuery:
    """Consulta DNS."""
    uid: str
    ts: str
    src_ip: str
    dst_ip: str
    proto: str
    query: str
    qtype: str
    rcode: str
    answers: List[str] = field(default_factory=list)
    ttl: List[float] = field(default_factory=list)


@dataclass
class SSLConnection:
    """Conexion SSL/TLS."""
    uid: str
    ts: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    version: str
    cipher: str
    subject: str = ""
    issuer: str = ""
    validation_status: str = ""


@dataclass
class SSHConnection:
    """Conexion SSH."""
    uid: str
    ts: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    status: str
    client: str = ""
    server: str = ""
    auth_method: str = ""
    auth_success: bool = False


@dataclass
class FTPTransfer:
    """Transferencia FTP."""
    uid: str
    ts: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    command: str
    arg: str
    resp_code: int = 0
    resp_msg: str = ""


@dataclass
class Notice:
    """Alerta de Zeek."""
    uid: str
    ts: str
    src_ip: str
    dst_ip: str
    msg: str
    note: str
    sub: str = ""
    dst_port: int = 0


# =============================================================================
# Clase Zeek Reader
# =============================================================================

class ZeekReader:
    """Lectura de logs Zeek."""

    FIELD_SEPARATOR = "\t"
    EMPTY_FIELD = "-"
    SET_SEPARATOR = ","

    def __init__(self, log_dir: str = None):
        self.log_dir = log_dir
        self.connections: List[Connection] = []
        self.http_requests: List[HTTPRequest] = []
        self.dns_queries: List[DNSQuery] = []
        self.ssl_connections: List[SSLConnection] = []
        self.ssh_connections: List[SSHConnection] = []
        self.ftp_transfers: List[FTPTransfer] = []
        self.notices: List[Notice] = []
        self.field_names: Dict[str, List[str]] = {}

    def _parse_timestamp(self, ts_str: str) -> float:
        """Parsea timestamp de Zeek."""
        try:
            if "." in ts_str:
                dt = datetime.strptime(ts_str.split(".")[0], "%Y-%m-%d-%H:%M:%S")
                return dt.timestamp()
            return float(ts_str)
        except:
            return 0.0

    def _empty_value(self, value: str) -> bool:
        """Verifica si el valor esta vacio."""
        return value in ("", self.EMPTY_FIELD, "-")

    def _to_int(self, value: str, default: int = 0) -> int:
        """Convierte a entero."""
        if self._empty_value(value):
            return default
        try:
            return int(value)
        except:
            return default

    def _to_float(self, value: str, default: float = 0.0) -> float:
        """Convierte a flotante."""
        if self._empty_value(value):
            return default
        try:
            return float(value)
        except:
            return default

    def _parse_set(self, value: str) -> List[str]:
        """Parsea valores separados por coma."""
        if self._empty_value(value):
            return []
        return [v.strip() for v in value.split(self.SET_SEPARATOR) if v.strip()]

    def _read_zeek_log(self, path: str) -> tuple:
        """Lee un log Zeek y retorna headers y registros."""
        if not os.path.exists(path):
            logger.error(f"Archivo no encontrado: {path}")
            return [], []

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if not lines:
            return [], []

        headers = []
        data_lines = []

        for line in lines:
            line = line.rstrip("\n\r")

            if line.startswith("#"):
                if line.startswith("#fields"):
                    headers = line.replace("#fields", "").strip().split(self.FIELD_SEPARATOR)
                continue

            if line:
                data_lines.append(line)

        return headers, data_lines

    def read_conn_log(self, path: str) -> List[Connection]:
        """Lee conn.log."""
        headers, lines = self._read_zeek_log(path)

        if not headers:
            logger.warning(f"Headers no encontrados en {path}")
            return []

        self.connections = []

        for line in lines:
            fields = line.split(self.FIELD_SEPARATOR)
            if len(fields) < len(headers):
                continue

            self.connections.append(Connection(
                uid=fields[headers.index("uid")] if "uid" in headers else "",
                orig_ip=fields[headers.index("id.orig_h")] if "id.orig_h" in headers else "",
                orig_port=self._to_int(fields[headers.index("id.orig_p")]),
                resp_ip=fields[headers.index("id.resp_h")] if "id.resp_h" in headers else "",
                resp_port=self._to_int(fields[headers.index("id.resp_p")]),
                proto=fields[headers.index("proto")] if "proto" in headers else "",
                duration=self._to_float(fields[headers.index("duration")]),
                orig_bytes=self._to_int(fields[headers.index("orig_bytes")]),
                resp_bytes=self._to_int(fields[headers.index("resp_bytes")]),
                conn_state=fields[headers.index("conn_state")] if "conn_state" in headers else "",
                local_orig=fields[headers.index("local_orig")] == "T" if "local_orig" in headers else False,
                local_resp=fields[headers.index("local_resp")] == "T" if "local_resp" in headers else False,
                missed_bytes=self._to_int(fields[headers.index("missed_bytes")]),
                orig_pkts=self._to_int(fields[headers.index("orig_pkts")]),
                resp_pkts=self._to_int(fields[headers.index("resp_pkts")]),
                orig_ip_bytes=self._to_int(fields[headers.index("orig_ip_bytes")]),
                resp_ip_bytes=self._to_int(fields[headers.index("resp_ip_bytes")]),
                ts=fields[headers.index("ts")] if "ts" in headers else "",
                service=fields[headers.index("service")] if "service" in headers else ""
            ))

        logger.info(f"Leidos {len(self.connections)} conexiones de {path}")
        return self.connections

    def read_http_log(self, path: str) -> List[HTTPRequest]:
        """Lee http.log."""
        headers, lines = self._read_zeek_log(path)

        if not headers:
            return []

        self.http_requests = []

        for line in lines:
            fields = line.split(self.FIELD_SEPARATOR)
            if len(fields) < len(headers):
                continue

            idx = lambda h: headers.index(h) if h in headers else -1

            self.http_requests.append(HTTPRequest(
                uid=fields[idx("uid")],
                id=fields[idx("id")],
                ts=fields[idx("ts")],
                src_ip=fields[idx("id.orig_h")],
                src_port=self._to_int(fields[idx("id.orig_p")]),
                dst_ip=fields[idx("id.resp_h")],
                dst_port=self._to_int(fields[idx("id.resp_p")]),
                method=fields[idx("method")],
                host=fields[idx("host")],
                uri=fields[idx("uri")],
                referrer=fields[idx("referrer")],
                user_agent=fields[idx("user_agent")],
                status_code=self._to_int(fields[idx("status_code")]),
                status_msg=fields[idx("status_msg")],
                response_body_len=self._to_int(fields[idx("response_body_len")]) if "response_body_len" in headers else 0,
                mime_type=fields[idx("mime_type")] if "mime_type" in headers else ""
            ))

        logger.info(f"Leidos {len(self.http_requests)} requests HTTP de {path}")
        return self.http_requests

    def read_dns_log(self, path: str) -> List[DNSQuery]:
        """Lee dns.log."""
        headers, lines = self._read_zeek_log(path)

        if not headers:
            return []

        self.dns_queries = []

        for line in lines:
            fields = line.split(self.FIELD_SEPARATOR)
            if len(fields) < len(headers):
                continue

            idx = lambda h: headers.index(h) if h in headers else -1

            self.dns_queries.append(DNSQuery(
                uid=fields[idx("uid")],
                ts=fields[idx("ts")],
                src_ip=fields[idx("id.orig_h")],
                dst_ip=fields[idx("id.resp_h")],
                proto=fields[idx("proto")],
                query=fields[idx("query")],
                qtype=fields[idx("qtype")],
                rcode=fields[idx("rcode")],
                answers=self._parse_set(fields[idx("answers")]),
                ttl=[self._to_float(t) for t in self._parse_set(fields[idx("TTL")])]
            ))

        logger.info(f"Leidas {len(self.dns_queries)} queries DNS de {path}")
        return self.dns_queries

    def read_ssl_log(self, path: str) -> List[SSLConnection]:
        """Lee ssl.log."""
        headers, lines = self._read_zeek_log(path)

        if not headers:
            return []

        self.ssl_connections = []

        for line in lines:
            fields = line.split(self.FIELD_SEPARATOR)
            if len(fields) < len(headers):
                continue

            idx = lambda h: headers.index(h) if h in headers else -1

            self.ssl_connections.append(SSLConnection(
                uid=fields[idx("uid")],
                ts=fields[idx("ts")],
                src_ip=fields[idx("id.orig_h")],
                src_port=self._to_int(fields[idx("id.orig_p")]),
                dst_ip=fields[idx("id.resp_h")],
                dst_port=self._to_int(fields[idx("id.resp_p")]),
                version=fields[idx("version")],
                cipher=fields[idx("cipher")],
                subject=fields[idx("subject")],
                issuer=fields[idx("issuer")],
                validation_status=fields[idx("validation_status")]
            ))

        logger.info(f"Leidos {len(self.ssl_connections)} conexiones SSL de {path}")
        return self.ssl_connections

    def read_ssh_log(self, path: str) -> List[SSHConnection]:
        """Lee ssh.log."""
        headers, lines = self._read_zeek_log(path)

        if not headers:
            return []

        self.ssh_connections = []

        for line in lines:
            fields = line.split(self.FIELD_SEPARATOR)
            if len(fields) < len(headers):
                continue

            idx = lambda h: headers.index(h) if h in headers else -1

            self.ssh_connections.append(SSHConnection(
                uid=fields[idx("uid")],
                ts=fields[idx("ts")],
                src_ip=fields[idx("id.orig_h")],
                dst_ip=fields[idx("id.resp_h")],
                src_port=self._to_int(fields[idx("id.orig_p")]),
                dst_port=self._to_int(fields[idx("id.resp_p")]),
                status=fields[idx("status")],
                client=fields[idx("client")],
                server=fields[idx("server")],
                auth_method=fields[idx("auth_method")],
                auth_success=fields[idx("auth_success")] == "true" if "auth_success" in headers else False
            ))

        logger.info(f"Leidas {len(self.ssh_connections)} conexiones SSH de {path}")
        return self.ssh_connections

    def read_ftp_log(self, path: str) -> List[FTPTransfer]:
        """Lee ftp.log."""
        headers, lines = self._read_zeek_log(path)

        if not headers:
            return []

        self.ftp_transfers = []

        for line in lines:
            fields = line.split(self.FIELD_SEPARATOR)
            if len(fields) < len(headers):
                continue

            idx = lambda h: headers.index(h) if h in headers else -1

            self.ftp_transfers.append(FTPTransfer(
                uid=fields[idx("uid")],
                ts=fields[idx("ts")],
                src_ip=fields[idx("id.orig_h")],
                dst_ip=fields[idx("id.resp_h")],
                src_port=self._to_int(fields[idx("id.orig_p")]),
                dst_port=self._to_int(fields[idx("id.resp_p")]),
                command=fields[idx("command")],
                arg=fields[idx("arg")],
                resp_code=self._to_int(fields[idx("resp_code")]),
                resp_msg=fields[idx("resp_msg")]
            ))

        logger.info(f"Leidas {len(self.ftp_transfers)} transferencias FTP de {path}")
        return self.ftp_transfers

    def read_notice_log(self, path: str) -> List[Notice]:
        """Lee notice.log."""
        headers, lines = self._read_zeek_log(path)

        if not headers:
            return []

        self.notices = []

        for line in lines:
            fields = line.split(self.FIELD_SEPARATOR)
            if len(fields) < len(headers):
                continue

            idx = lambda h: headers.index(h) if h in headers else -1

            self.notices.append(Notice(
                uid=fields[idx("uid")],
                ts=fields[idx("ts")],
                src_ip=fields[idx("id.orig_h")],
                dst_ip=fields[idx("id.resp_h")],
                msg=fields[idx("msg")],
                note=fields[idx("note")],
                sub=fields[idx("sub")],
                dst_port=self._to_int(fields[idx("id.resp_p")])
            ))

        logger.info(f"Leidos {len(self.notices)} avisos de {path}")
        return self.notices

    def read_all_logs(self, log_dir: str = None) -> Dict[str, Any]:
        """Lee todos los logs Zeek en un directorio."""
        log_dir = log_dir or self.log_dir
        if not log_dir or not os.path.isdir(log_dir):
            logger.error(f"Directorio no valido: {log_dir}")
            return {}

        results = {}

        log_mappings = {
            "conn.log": self.read_conn_log,
            "http.log": self.read_http_log,
            "dns.log": self.read_dns_log,
            "ssl.log": self.read_ssl_log,
            "ssh.log": self.read_ssh_log,
            "ftp.log": self.read_ftp_log,
            "notice.log": self.read_notice_log
        }

        for log_file, reader_fn in log_mappings.items():
            path = os.path.join(log_dir, log_file)
            if os.path.exists(path):
                results[log_file] = reader_fn(path)

        return results

    def correlate_events(self) -> List[Dict]:
        """Correlaciona eventos entre diferentes logs."""
        correlations = []

        uid_map = defaultdict(list)

        for conn in self.connections:
            uid_map[conn.uid].append(("conn", conn))

        for http in self.http_requests:
            uid_map[http.uid].append(("http", http))

        for dns in self.dns_queries:
            uid_map[dns.uid].append(("dns", dns))

        for ssl in self.ssl_connections:
            uid_map[ssl.uid].append(("ssl", ssl))

        for ssh in self.ssh_connections:
            uid_map[ssh.uid].append(("ssh", ssh))

        for uid, events in uid_map.items():
            if len(events) > 1:
                correlations.append({
                    "uid": uid,
                    "events": [e[0] for e in events],
                    "count": len(events)
                })

        logger.info(f"Correlacionados {len(correlations)} eventos")
        return correlations

    def get_stats(self) -> Dict:
        """Obtiene estadisticas de los logs."""
        return {
            "connections": len(self.connections),
            "http_requests": len(self.http_requests),
            "dns_queries": len(self.dns_queries),
            "ssl_connections": len(self.ssl_connections),
            "ssh_connections": len(self.ssh_connections),
            "ftp_transfers": len(self.ftp_transfers),
            "notices": len(self.notices)
        }

    def find_connections_by_ip(self, ip: str) -> List[Connection]:
        """Busca conexiones por IP."""
        return [c for c in self.connections if c.orig_ip == ip or c.resp_ip == ip]

    def find_dns_by_query(self, query: str) -> List[DNSQuery]:
        """BuscaDNS por nombre de dominio."""
        return [d for d in self.dns_queries if query in d.query]

    def find_notices_by_type(self, note_type: str) -> List[Notice]:
        """Busca avisos por tipo."""
        return [n for n in self.notices if n.note == note_type]