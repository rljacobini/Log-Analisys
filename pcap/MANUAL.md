# Manual del Módulo PCAP Analyzer

**Version:** 1.0.0
**Fecha:** 20 de Abril 2026

---

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[IMPLEMENTACION-PCAP](../docs/IMPLEMENTACION-PCAP.md)** - Especificación técnica
- 📄 **[Seguridad](../docs/Seguridad.md)** - Medidas de seguridad

---

## 1. Resumen

El módulo PCAP Analyzer analiza archivos de captura de paquetes de red para detectar comportamiento malicioso y generar eventos compatibles con la plataforma SOC.

### Formatos Soportados

| Formato | Extension | Descripcion |
|---------|-----------|-------------|
| PCAP | .pcap, .cap | Formato libpcap standard |
| PCAPNG | .pcapng, .ng | Next Generation PCAP |
| Zeek | directorio/ | Logs de Zeek (conn.log, http.log, etc.) |

### Analisis Realizados

- Reconstrucción de sesiones TCP/UDP
- Detección de escaneos de puertos
- Detección de ataques de fuerza bruta
- Detección de inundación SYN/ICMP/UDP
- Detección de MITM (ARP spoofing, DNS poisoning)
- Detección de exfiltración de datos

---

## 2. Inicio Rápido

### Requisitos

```bash
pip install requests python-dotenv
```

### Analisis Básico de PCAP

```bash
python run_pcap captura.pcap
```

### Analisis de PCAPNG

```bash
python run_pcap captura.pcapng --format pcapng
```

### Analisis de Logs Zeek

```bash
python run_pcap /var/log/zeek/ --format zeek
```

### Con Envío al Servidor SOC

```bash
python run_pcap captura.pcap \
    --server-url https://soc-server:5000/log \
    --api-key tu-clave-secreta
```

---

## 3. Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                    PCAP ANALYZER                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐    │
│  │ PCAP Reader │  │PCAPNG Reader│  │   Zeek Reader           │    │
│  │  (.pcap)    │  │ (.pcapng)   │  │  (conn,http,dns,ssl)   │    │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘    │
│         │                │                     │                  │
│         └────────┬───────┘                     │                  │
│                  ▼                            │                  │
│         ┌────────────────┐                    │                  │
│         │   Normalizer   │◀─────────────────────┘                  │
│         │   to Common    │                                     │
│         │   Format      │                                     │
│         └───────┬───────┘                                     │
│                 ▼                                            │
│  ┌─────────────┐    ┌─────────────┐    ┌────────���────┐     │
│  │  Session    │───▶│  Attack    │───▶│   SOC       │     │
│  │  Analyzer   │    │  Detector  │    │   Events   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                             │              │
└─────────────────────────────────────────────┼──────────────┘
                                              │
                                              ▼
                                    ┌─────────────────────┐
                                    │    SOC Server       │
                                    │    (/log endpoint) │
                                    └─────────────────────┘
```

---

## 4. Modulos

### 4.1 pcap_reader.py

Lee y parsea archivos PCAP (libpcap format).

**Clases:**

| Clase | Descripcion |
|-------|-------------|
| `Packet` | Paquete capturando con todos los campos |
| `Session` | Sesion de comunicacion |

**Métodos:**

```python
from pcap.pcap_reader import PCAPReader

reader = PCAPReader("capture.pcap")
packets = reader.read_packets()
tcp_packets = reader.filter_by_protocol("tcp")
ip_packets = reader.filter_by_ip("192.168.1.100", direction="src")
sessions = reader.get_sessions()
stats = reader.get_stats()
reader.close()
```

### 4.2 pcapng_reader.py

Lee y parsea archivos PCAPNG (Next Generation).

**Clases:**

| Clase | Descripcion |
|-------|-------------|
| `Section` | Seccion PCAPNG |
| `Interface` | Interfaz de captura |
| `Packet` | Paquete PCAPNG |

**Métodos:**

```python
from pcap.pcapng_reader import PCAPNGReader

reader = PCAPNGReader("capture.pcapng")
packets = reader.read_packets()
sections = reader.get_sections()
interfaces = reader.get_interfaces()
reader.close()
```

### 4.3 zeek_reader.py

Lee y parsea logs de Zeek.

**Clases:**

| Clase | Descripcion |
|-------|-------------|
| `Connection` | Conexion de red (conn.log) |
| `HTTPRequest` | Peticion HTTP (http.log) |
| `DNSQuery` | Consulta DNS (dns.log) |
| `SSLConnection` | Conexion SSL (ssl.log) |
| `SSHConnection` | Conexion SSH (ssh.log) |
| `FTPTransfer` | Transferencia FTP (ftp.log) |
| `Notice` | Alerta (notice.log) |

**Métodos:**

```python
from pcap.zeek_reader import ZeekReader

reader = ZeekReader()
reader.read_conn_log("conn.log")
reader.read_http_log("http.log")
reader.read_dns_log("dns.log")
reader.read_ssl_log("ssl.log")
reader.read_all_logs("/var/log/zeek/")

correlations = reader.correlate_events()
stats = reader.get_stats()
```

### 4.4 session_analyzer.py

Analiza sesiones de red y detecta anomalías.

**Clases:**

| Clase | Descripcion |
|-------|-------------|
| `SessionStats` | Estadisticas de una sesion |
| `AttackEvent` | Evento de ataque detectado |

**Metodos:**

```python
from pcap.session_analyzer import SessionAnalyzer

analyzer = SessionAnalyzer(packets)
sessions = analyzer.build_sessions()

port_scans = analyzer.detect_port_scans(threshold=20)
syn_floods = analyzer.detect_syn_flood(threshold=50)
brute_force = analyzer.detect_brute_force(port=22, threshold=5)
anomalies = analyzer.detect_anomalies()

top_talkers = analyzer.get_top_talkers(10)
summary = analyzer.get_connection_summary()
```

### 4.5 attack_detector.py

Detecta diferentes tipos de ataques en tráfico de red.

**Clases:**

| Clase | Descripcion |
|-------|-------------|
| `Attack` | Ataque detectado con metadata MITRE |

**Detecciones:**

| Tipo | Metodo | Severidad |
|------|-------|-----------|
| Port Scan | `detect_port_scan()` | HIGH |
| Host Discovery | `detect_host_discovery()` | MEDIUM |
| SYN Flood | `detect_syn_flood()` | CRITICAL |
| ICMP Flood | `detect_icmp_flood()` | HIGH |
| UDP Flood | `detect_udp_flood()` | HIGH |
| SSH Brute Force | `detect_ssh_brute_force()` | HIGH |
| FTP Brute Force | `detect_ftp_brute_force()` | HIGH |
| HTTP Brute Force | `detect_http_brute_force()` | HIGH |
| ARP Spoofing | `detect_arp_spoofing()` | HIGH |
| DNS Poisoning | `detect_dns_poisoning()` | CRITICAL |
| SSL Strip | `detect_ssl_strip()` | MEDIUM |
| Data Exfiltration | `detect_data_exfiltration()` | HIGH |
| C2 Traffic | `detect_c2_traffic()` | CRITICAL |
| DNS Tunneling | `detect_dns_tunneling()` | HIGH |

**用法:**

```python
from pcap.attack_detector import AttackDetector

detector = AttackDetector(packets=packets)
attacks = detector.detect_all()

by_severity = detector.get_attacks_by_severity()
summary = detector.get_summary()
```

### 4.6 pcap_analyzer.py

Analizador principal que coordina todos los módulos.

**Clase Principal:**

```python
from pcap.pcap_analyzer import PCAPAnalyzer

analyzer = PCAPAnalyzer("capture.pcap", input_type="auto")
results = analyzer.analyze()

events = analyzer.get_events()

analyzer.send_to_server(
    server_url="https://soc:5000/log",
    api_key="tu-clave",
    secret="tu-secret",
    verify_ssl=True
)
```

---

## 5. Eventos Generados

Formato compatible con el agente SOC:

```json
{
  "agent_id": "pcap-analyzer-01",
  "src_ip": "192.168.1.100",
  "dst_ip": "192.168.1.1",
  "dst_port": 22,
  "risk": 50,
  "attack_type": "port_scan",
  "target_host": "192.168.1.1",
  "source": "pcap_analysis_pcap",
  "severity": "HIGH",
  "event_time": "2026-04-20T10:30:00",
  "raw_log": "Port scan: 50 puertos escaneados",
  "extra_data": {
    "mitre_technique": "T1046",
    "evidence": ["Scanned 50 ports"],
    "indicators": {
      "scanned_ports": 50,
      "threshold": 15
    }
  }
}
```

---

## 6. Configuración

### Variables de Entorno

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `PCAP_AGENT_ID` | Identificador del analizador | pcap-analyzer-01 |
| `SERVER_URL` | URL del servidor SOC | https://localhost:5000/log |
| `X_API_KEY` | Clave API | changeme |
| `X_API_KEY_SECRET` | Secret para HMAC | - |
| `INPUT_FORMAT` | Formato de entrada | auto |
| `ZEEK_LOG_DIR` | Directorio de logs Zeek | - |
| `PORT_SCAN_THRESHOLD` | Puertos para port scan | 15 |
| `SYN_FLOOD_THRESHOLD` | SYN para flood | 50 |
| `BRUTE_FORCE_THRESHOLD` | Intentos para fuerza bruta | 5 |

### Archivo .env

Copiar `pcap/.env.example` a `pcap/.env` y configurar.

**Configuracion importante:**

```env
# Servidor (HTTPS obligatorio)
SERVER_URL=https://localhost:5000/log

# API Key
X_API_KEY=tu-clave-api
```

> **Nota:** El servidor requiere HTTPS. Verificar que `SERVER_URL` use `https://` no `http://`.

---

## 7. Comandos CLI

### help

```bash
python run_pcap --help
```

### Análisis básico

```bash
python run_pcap captura.pcap
```

### Análisis con output JSON

```bash
python run_pcap captura.pcap --output results.json
```

### Análisis verbose

```bash
python run_pcap captura.pcap --verbose
```

### Con envío al servidor

```bash
python run_pcap captura.pcap \
    --server-url https://soc:5000/log \
    --api-key tu-clave \
    --api-secret tu-secret
```

### Formato Zeek

```bash
python run_pcap /var/log/zeek/ --format zeek
```

---

## 8. Detección de Amenazas

### Niveles de Severidad

| Nivel | Rango de Riesgo | Descripcion |
|-------|-----------------|-------------|
| LOW | 0-14 | Información |
| MEDIUM | 15-29 | Alerta informativa |
| HIGH | 30-49 | requiere atención |
| CRITICAL | 50+ | Acción inmediata |

### Técnicas MITRE ATT&CK

| Ataque | ID MITRE |
|--------|----------|
| Port Scan | T1046 |
| SYN Flood | T1498 |
| Brute Force | T1110 |
| ARP Spoofing | T1557 |
| DNS Poisoning | T1651 |
| Data Exfiltration | T1041 |
| C2 Traffic | T1071 |

---

## 9. Integración con SOC

### Envío de Eventos

El analizador envía eventos directamente al servidor SOC:

```python
analyzer = PCAPAnalyzer("capture.pcap")
analyzer.analyze()

analyzer.send_to_server(
    server_url="https://soc:5000/log",
    api_key="tu-clave",
    secret="tu-secret"
)
```

### Autenticación

- **X-API-Key**: Header de autenticación básico
- **X-Request-Signature**: HMAC-SHA256 (opcional, si `X_API_KEY_SECRET` configurado)

---

## 10. Rendimiento

### Límites Recomendados

| Parametro | Valor | Descripcion |
|-----------|-------|-------------|
| `MAX_PACKETS_MEMORY` | 100000 | Paquetes en memoria |
| `SESSION_TIMEOUT` | 300s | Timeout de sesión |

### Optimización

- Para archivos grandes, procesar en batches
- Usar `--output` para guardar resultados
- Habilitar solo detecciones necesarias en `.env`

---

## 11. Troubleshooting

### Error: "No packets found"

- Verificar que el archivo PCAP no esté vacío
- Verificar que el formato sea correcto

### Error: "Connection refused"

- Verificar que el servidor SOC esté corriendo
- Verificar `SERVER_URL` en configuración

### Error: "SSL verification failed"

- Usar `--verify-ssl=false` para desarrollo
- En producción, configurar certificados válidos

### Error: "Timeout"

- Aumentar timeout en配置
- Verificar conectividad de red

---

## 12. Ejemplos

### Ejemplo 1: Análisis Básico

```python
from pcap.pcap_analyzer import PCAPAnalyzer

analyzer = PCAPAnalyzer("captura.pcap")
results = analyzer.analyze()

print(f"Ataques detectados: {results['attacks_detected']}")
for attack in results['attacks']:
    print(f"  - {attack['attack_type']}: {attack['description']}")
```

### Ejemplo 2: Análisis con Filtrado

```python
from pcap.pcap_reader import PCAPReader

reader = PCAPReader("captura.pcap")
packets = reader.read_packets()

# Filtrar solo tráfico TCP al puerto 22
ssh_packets = [
    p for p in packets
    if p.protocol == "tcp" and p.dst_port == 22
]

print(f"Paquetes SSH: {len(ssh_packets)}")
```

### Ejemplo 3: Detección Personalizada

```python
from pcap.attack_detector import AttackDetector

detector = AttackDetector(packets=packets)

# Solo detectar port scans
scans = detector.detect_port_scan(threshold=10)
print(f"Port scans: {len(scans)}")

# Solo detectar SYN flood
syn_floods = detector.detect_syn_flood(threshold=100)
print(f"SYN floods: {len(syn_floods)}")
```

---

## 13. Dependencias

```bash
pip install requests python-dotenv
```

---

## Version History

| Version | Fecha | Cambios |
|---------|-------|----------|
| 1.0.0 | 2026-04-20 | Version inicial |
| 1.1.0 | 2026-04-21 | HTTPS por defecto, retry con backoff, deduplicacion mejorada, timestamps por ataque |

## Mejoras Recientes (v1.1.0)

### HTTPS por Defecto
- SERVER_URL ahora usa HTTPS por defecto
- El servidor requiere HTTPS

### Retry con Exponential Backoff
- Reintento automatico en caso de error de conexion
- Delay inicial: 5 segundos
- Delay maximo: 120 segundos
- Maximo 3 reintentos

### Deduplicacion Mejorada
- Agrupa eventos por `(attack_type, src_ip)` en lugar de enviar cada paquete
- Reduce spam de eventos duplicados
- Especialmente util para `suspicious_download` y `possible_c2`

### Timestamps por Ataque
- Cada ataque tiene su propio timestamp del paquete
- No usa el timestamp global del PCAP
- Formato: `YYYY-MM-DD HH:MM:SS.ffffff`

### Formato extra_data
- Ahora es JSON string como los agentes
- Incluye: mitre_technique, evidence, indicators