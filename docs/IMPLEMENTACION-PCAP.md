# Implementacion de PCAP Analyzer - TCPdump

**Fecha:** 20 de Abril 2026
**Version:** 5.0

---

> **Nota:** El modulo PCAP ya esta implementado en `pcap/`. Ver `pcap/MANUAL.md` para documentacion detallada.

---

---

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[Seguridad](Seguridad.md)** - Medidas de seguridad

---

## 1. Resumen del Proyecto

Desarrollar un modulo `pcap_analyzer.py` que analice archivos de captura de paquetes (PCAP) para detectar comportamiento malicioso en tráfico de red y reportar eventos al servidor SOC central.

### Objetivo

- Analizar archivos PCAP offline
- Detectar ataques y tráfico malicioso
- Integrar con la plataforma SOC existente
- Soportar multiples tipos de ataques

---

## 2. Fuentes de Datos Soportadas

### Capturas de Red

| Fuente | Descripcion |
|--------|-------------|
| tcpdump | Capturas standard de Linux/Unix |
| Wireshark | Exportaciones PCAP/PCAPNG |
| TShark | Version CLI de Wireshark |
| netsniff-ng | Captura rapida de red |
| Generado por IDS | Alertas de Suricata/Zeek |
| **PCAPNG** | Next Generation PCAP (multiple secciones) |

### Zeek Logs

| Log | Descripcion | Uso Principal |
|-----|-------------|--------------|
| conn.log | Conexiones de red | Analisis de tráfico |
| http.log | Peticiones HTTP | Análisis web |
| dns.log | Consultas DNS | Analisis DNS |
| ssh.log | Conexiones SSH | Detección brute force |
| ftp.log | Transferencias FTP | Analisis FTP |
| ssl.log | Negociaciones SSL/TLS | Análisis TLS |
| notice.log | Alertas de Zeek | Integración alertas |

### Tipo de Trafico

| Capa | Protocolos |
|------|-------------|
| Red | IP, ICMP, ARP |
| Transporte | TCP, UDP |
| Aplicacion | HTTP, DNS, SSH, FTP, SMTP, SMB |

---

## 3. Arquitectura Propuesta

```
┌─────────────────────────────────────────────────────────────────┐
│                      PCAP ANALYZER v2.0                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ PCAP Reader  │  │PCAPNG Reader│  │   Zeek Reader           │  │
│  │  (.pcap)    │  │ (.pcapng)   │  │  (conn,dns,http,ssh)   │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                     │                │
│         └────────┬───────┘                     │                │
│                  ▼                            │                │
│         ┌────────────────┐                    │                │
│         │   Normalizer   │◀─────────────────────┘                │
│         │   to Common    │                                     │
│         │   Format      │                                     │
│         └───────┬───────┘                                     │
│                 ▼                                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  Parser     │───▶│  Session    │───▶│  Detector  │     │
│  │  Sessions  │    │  Analyzer   │    │  Attacks   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                           │                  │             │
│                           ▼                  ▼             │
│                    ┌─────────────┐    ┌─────────────┐     │
│                    │  Analyzer   │    │  Reporter   │     │
│                    │  Behavior   │    │  SOC       │     │
│                    └─────────────┘    └─────────────┘     │
│                                             │             │
└─────────────────────────────────────────────┼─────────────┘
                                              │
                                              ▼
                                    ┌─────────────────────┐
                                    │    SOC Server       │
                                    │    (/log endpoint) │
                                    └─────────────────────┘
```

---

## 4. Modulos a Implementar

### 4.1 pcap_reader.py

Lee y parsea archivos PCAP.

```python
class PCAPReader:
    """Lectura de archivos PCAP."""

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = []

    def read_packets(self) -> list:
        """Lee todos los paquetes."""

    def filter_by_protocol(self, protocol: str) -> list:
        """Filtra por protocolo."""

    def filter_by_ip(self, ip: str, direction: str) -> list:
        """Filtra por IP (src/dst/both)."""

    def get_session(self, src_ip: str, dst_ip: str) -> list:
        """Obtiene packets de una sesion."""
```

### 4.1b pcapng_reader.py

Lee y parsea archivos PCAPNG (Next Generation).

```python
class PCAPNGReader:
    """Lectura de archivos PCAPNG."""

    def __init__(self, pcapng_file: str):
        self.pcapng_file = pcapng_file
        self.packets = []
        self.sections = []

    def read_packets(self) -> list:
        """Lee todos los paquetes."""

    def get_sections(self) -> list:
        """Obtiene las secciones del archivo."""

    def filter_by_interface(self, interface_id: int) -> list:
        """Filtra por interfaz."""

    def get_timestamp_resolution(self) -> tuple:
        """Obtiene resolucion de timestamp."""
```

### 4.1c zeek_reader.py

Lee y parsea logs de Zeek.

```python
class ZeekReader:
    """Lectura de logs Zeek."""

    def __init__(self, log_dir: str = None, log_files: list = None):
        self.log_dir = log_dir
        self.log_files = log_files or []
        self.connections = []
        self.http_logs = []
        self.dns_logs = []
        self.ssh_logs = []

    def read_conn_log(self, path: str) -> list:
        """Lee conn.log."""

    def read_http_log(self, path: str) -> list:
        """Lee http.log."""

    def read_dns_log(self, path: str) -> list:
        """Lee dns.log."""

    def read_all_logs(self, log_dir: str) -> dict:
        """Lee todos los logs en directorio."""

    def correlate_events(self) -> list:
        """Correlaciona eventos entre logs."""
```

### 4.2 session_analyzer.py

Analiza sesiones de red.

```python
class SessionAnalyzer:
    """Analisis de sesiones TCP."""
    
    def __init__(self, packets: list):
        self.packets = packets
    
    def build_sessions(self) -> dict:
        """Construye diccionario de sesiones."""
    
    def analyze_tcp_flags(self, session: list) -> dict:
        """Analiza flags TCP (SYN, FIN, RST, etc)."""
    
    def detect_port_scans(self) -> list:
        """Detecta escaneos de puertos."""
    
    def detect_brute_force(self) -> list:
        """Detecta fuerza bruta en servicios."""
```

### 4.3 attack_detector.py

Detector de ataques.

```python
class AttackDetector:
    """Detector de ataques en trafico PCAP."""
    
    def detect_port_scan(self, packets: list) -> AttackEvent:
        """Escaneo de puertos."""
    
    def detect_syn_flood(self, packets: list) -> AttackEvent:
        """SYN flood (DoS)."""
    
    def detect_arpspoof(self, packets: list) -> AttackEvent:
        """ARP spoofing."""
    
    def detect_dns_poisoning(self, packets: list) -> AttackEvent:
        """DNS poisoning."""
    
    def detect_ssl_strip(self, packets: list) -> AttackEvent:
        """SSL stripping."""
    
    def detect_data_exfiltration(self, packets: list) -> AttackEvent:
        """Exfiltracion de datos."""
```

### 4.4 pcap_analyzer.py

Analizador principal.

```python
class PCAPAnalyzer:
    """Analizador principal de archivos PCAP."""

    def __init__(self, input_file: str, input_type: str = "auto"):
        self.input_file = input_file
        self.input_type = input_type
        self.reader = None
        self.sessions = {}
        self.events = []

    def detect_format(self) -> str:
        """Detecta el formato de entrada (pcap/pcapng/zeek)."""

    def analyze(self) -> list:
        """Ejecuta analisis completo."""

    def analyze_pcap(self) -> list:
        """Analiza archivo PCAP."""

    def analyze_pcapng(self) -> list:
        """Analiza archivo PCAPNG."""

    def analyze_zeek_logs(self) -> list:
        """Analiza logs Zeek."""

    def get_events(self) -> list:
        """Retorna lista de eventos detectados."""

    def send_to_server(self, server_url: str, api_key: str):
        """Envia eventos al servidor SOC."""
```

---

## 5. Tipos de Ataques a Detectar

### 5.1 Reconocimiento

| Ataque | Descripcion | Indicador |
|--------|-------------|-----------|
| Port Scan | Escaneo de puertos | Multiples puertos en misma IP |
| Host Discovery | Ping sweep | Multiples ICMP echo |
| OS Fingerprinting | Identificacion de SO | Paquetes con opciones TCP |

### 5.2 Fuerza Bruta

| Ataque | Descripcion | Indicador |
|--------|-------------|-----------|
| SSH Brute Force | Intentos multiples de login | Multiples AUTH failed |
| FTP Brute Force | Intentos de FTP | Multiple USER attempts |
| HTTP Auth | Fuerza bruta en web | Multiples 401 responses |

### 5.3 DoS/DDoS

| Ataque | Descripcion | Indicador |
|--------|-------------|-----------|
| SYN Flood | Inundacion SYN | Multiples SYN sin respuesta |
| ICMP Flood | Inundacion ICMP | Ping大量 |
| UDP Flood | Inundacion UDP | Multiplo Datagramas |

### 5.4 Man in the Middle

| Ataque | Descripcion | Indicador |
|--------|-------------|-----------|
| ARP Spoofing | Suplantacion ARP | Multiples respuestas ARP |
| DNS Poisoning | Envenenamiento DNS | Respuestas DNS不一致 |
| SSL Strip | downgrade SSL | Request HTTP antes de HTTPS |

### 5.5 Exfiltration

| Ataque | Descripcion | Indicador |
|--------|-------------|-----------|
| Large Data Transfer | Datos grandes | Volumen anómalo |
| C2 Communication | Comandos a C2 | Traffic a IPs desconocidas |
| DNS Tunneling | Tunel DNS | Queries DNS largas |

---

## 6. Eventos Generados

Formato compatible con agente:

```python
{
    "agent_id": "pcap-analyzer-01",
    "src_ip": "192.168.1.100",
    "risk": 50,
    "attack_type": "port_scan_detected",
    "target_host": "192.168.1.1",
    "target_port": "1-1024",
    "source": "pcap_analysis",
    "severity": "HIGH",
    "event_time": "2026-04-18T10:30:00",
    "raw_log": "Detected TCP port scan: 1024 ports scanned from 192.168.1.100 to 192.168.1.1",
    "extra_data": {
        "pcap_file": "/path/to/capture.pcap",
        "packets_count": 50000,
        "scanned_ports": [21, 22, 23, 25, ...],
        "duration_seconds": 120
    }
}
```

---

## 7. Configuracion

### Variables de Entorno

```env
# Identificacion
PCAP_AGENT_ID=pcap-analyzer-01

# Servidor
SERVER_URL=https://soc-server:5000/log
X_API_KEY=your-secret-key
X_API_KEY_SECRET=

# Formato de entrada
INPUT_FORMAT=auto  # auto, pcap, pcapng, zeek
ZEEK_LOG_DIR=/var/log/bro/current

# Analisis
ANALYZE_TCP_FLAGS=true
ANALYZE_UDP=true
ANALYZE_ICMP=true
DETECT_SCANS=true
DETECT_BRUTE_FORCE=true
DETECT_DOS=true
DETECT_MITM=true
DETECT_EXFILTRATION=true

# Rendimiento
MAX_PACKETS_MEMORY=100000
SESSION_TIMEOUT=300
```

### Opciones de Linea de Comandos

```bash
# Analisis PCAP
python pcap_analyzer.py captura.pcap \
    --agent-id pcap-01 \
    --server-url https://soc-server:5000/log \
    --api-key secret \
    --scan-detect \
    --brute-force-detect \
    --dos-detect \
    --verbose

# Analisis PCAPNG
python pcap_analyzer.py captura.pcapng \
    --format pcapng \
    --verbose

# Analisis Zeek logs
python pcap_analyzer.py /var/log/zeek/ \
    --format zeek \
    --verbose

# Zeek logs desde directorio
python pcap_analyzer.py /var/log/bro/current/ \
    --format zeek \
    --conn-log conn.log \
    --http-log http.log \
    --dns-log dns.log \
    --verbose
```

---

## 8. Implementacion por Fases

### Fase 1: Lectura de PCAP/PCAPNG (3 horas)

- [ ] Instalar `scapy` o `pyshark`
- [ ] Implementar PCAPReader
- [ ] Implementar PCAPNGReader
- [ ] Extraer paquetes basicos
- [ ] Filtrado por protocolo

### Fase 2: Analisis de Sesiones (3 horas)

- [ ] Reconstruir sesiones TCP
- [ ] Analizar flags TCP
- [ ] Calcular metricas de sesion
- [ ] Detectar patrones anómalos

### Fase 2b: Lectura de Zeek Logs (3 horas)

- [ ] Implementar ZeekReader
- [ ] Parsear conn.log (JSON/ASCII)
- [ ] Parsear http.log, dns.log, ssh.log
- [ ] Correlacionar eventos entre logs

### Fase 3: Deteccion de Ataques (4 horas)

- [ ] Port scan detection
- [ ] SYN flood detection
- [ ] Brute force detection
- [ ] ARP spoofing detection

### Fase 4: Integracion SOC (2 horas)

- [ ] Formato de eventos compatible
- [ ] Envio al servidor
- [ ] Retry con backoff
- [ ] Logging

### Fase 5: Pruebas y Documentacion (2 horas)

- [ ] pruebas con PCAPs conocidos
- [ ] Casos edge
- [ ] Manual de uso

---

## 9. Dependencias

```txt
scapy>=2.5.0
pyshark>=0.6
dpkt>=1.9.2
python-dotenv>=1.0
requests>=2.31
zeek2json>=0.2  # Conversion Zeek logs
scikit-learn>=1.3
xgboost>=1.7
mlflow>=2.0
```

---

## 10. Estructura de Archivos

```
agent/
├── pcap_analyzer.py      # Analizador principal
├── pcap_reader.py        # Lectura de PCAP
├── pcapng_reader.py      # Lectura de PCAPNG
├── zeek_reader.py       # Lectura de Zeek logs
├── session_analyzer.py   # Analisis de sesiones
├── attack_detector.py   # Deteccion de ataques
├── config.py             # Configuracion
└── .env.example         # Ejemplo de configuracion
```

---

## 11. Pruebas

### PCAPs de Prueba

| Archivo | Descripcion | Ataque |
|---------|-------------|-------|
| `test_port_scan.pcap` | Escaneo de puertos | Port Scan |
| `test_syn_flood.pcap` | SYN flood | DoS |
| `test_bruteforce.pcap` | Fuerza bruta SSH | Brute Force |
| `test_arpspoof.pcap` | ARP spoofing | MITM |
| `test_capture.pcapng` | Captura PCAPNG | Multiple |

### Zeek Logs de Prueba

| Archivo | Descripcion | Uso |
|---------|-------------|-----|
| `conn.log` | Conexiones | Analisis de trafico |
| `http.log` | HTTP requests | Analisis web |
| `dns.log` | DNS queries | Analisis DNS |
| `ssh.log` | SSH connections | Brute force |
| `notice.log` | Alertas Zeek | Integracion |

### Ejecution de Pruebas

```bash
# Analisis basico PCAP
python pcap_analyzer.py captura.pcap

# Analisis PCAPNG
python pcap_analyzer.py captura.pcapng --format pcapng

# Analisis Zeek logs
python pcap_analyzer.py /path/to/zeek/logs/ --format zeek

# Con envio al servidor
python pcap_analyzer.py captura.pcap --send-to-server

# Modo verbose
python pcap_analyzer.py captura.pcap --verbose
```

---

## 12. Checklist de Implementacion

### v1.0 (Basico)
- [ ] pcap_reader.py implementado
- [ ] session_analyzer.py implementado
- [ ] attack_detector.py con 5+ detectores
- [ ] pcap_analyzer.py integrado con SOC
- [ ] Pruebas con PCAPs conocidos
- [ ] Documentacion actualizada

### v2.0 (Formatos)
- [ ] pcapng_reader.py implementado
- [ ] zeek_reader.py implementado
- [ ] Pruebas con PCAPNG
- [ ] Pruebas con Zeek logs

### v3.0 (Live + ML)
- [ ] LiveCapture con scapy implementado
- [ ] CircularBuffer para streaming
- [ ] FeatureExtractor para ML
- [ ] MLDetector con modelo entrenado
- [ ] MLTrainer con pipeline completo
- [ ] Integracion Live + ML operativa
- [ ] Pruebas en entorno controlado

---

## 13. Roadmap Futuro

### Funcionalidades Implementadas (v4.0)

- Soporte para PCAPNG
- Integracion con Zeek logs
- Live Capture (analisis en tiempo real)
- Machine Learning para deteccion de anomalias
- Base de datos para ML (datasets, modelos, feedback)

### Mejoras a Corto Plazo

- Soporte para formatos adicionales (NetFlow, sFlow)
- TLS fingerprinting
- Protocolo especifico analisis (HTTP, DNS)

### Mejoras a Mediano Plazo

- Integracion con SIEM
- Analisis distribuido
- Deteccion basada en comportamientos

---

## 14. Live Capture (Analisis en Tiempo Real)

### 14.1 Descripcion

Permite analizar tráfico de red en tiempo real capturando paquetes directamente de una interfaz de red, sin necesidad de archivos PCAP pre-existentes.

### 14.2 Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                    LIVE CAPTURE MODULE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
│  │   Sniffer  │───▶│   Buffer   │───▶│  Detector   │           │
│  │  (scapy)   │    │ Circular   │    │  Streaming  │           │
│  └─────────────┘    └─────────────┘    └──────┬──────┘           │
│                                             │                  │
│                                             ▼                  │
│                                      ┌─────────────┐            │
│                                      │  Reporter  │            │
│                                      │    (SOC)   │            │
│                                      └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### 14.3 Modulo a Implementar

```python
class LiveCapture:
    """Captura de red en tiempo real."""

    def __init__(self, interface: str = None, bpf_filter: str = None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.buffer = CircularBuffer(max_size=5000)
        self.running = False

    def start(self):
        """Inicia captura."""

    def stop(self):
        """Detiene captura."""

    def process_batch(self, packets: list):
        """Procesa lote de paquetes."""

    def get_buffer(self) -> list:
        """Retorna buffer actual."""
```

### 14.4 Parametros

| Parametro | Descripcion | Default |
|-----------|-------------|----------|
| `--live` | Habilitar modo live | false |
| `--iface` | Interfaz de red | all |
| `--buffer-size` | Tamano del buffer | 5000 |
| `--flush-interval` | Intervalo de procesamiento (seg) | 5 |
| `--bpf-filter` | Filtro BPF (tcp, udp, port 80) | None |

### 14.5 Consideraciones

- Requiere privilegios root para capturar
- Usar BPF para filtrar trafego y reducir carga
- Buffer circular para evitar consumo de memoria excesivo
- Alertas en tiempo real al servidor SOC
- Latencia mínima entre captura y deteccion

---

## 15. Machine Learning para Deteccion de Anomalias

### 15.1 Descripcion

Utiliza modelos de ML para detectar comportamento anomalo y clasificar ataques basandose en patrones aprendido de datos historicos.

### 15.2 Arquitectura General

```
┌─────────────────────────────────────────────────────────────────┐
│                   ML TRAINING PIPELINE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
│  │   Dataset   │───▶│  Feature    │───▶│    Train    │           │
│  │  (labeled)  │    │  Extraction│    │    Model   │           │
│  └─────────────┘    └─────────────┘    └──────┬──────┘           │
│                                               │                  │
│                                               ▼                  │
│                                      ┌─────────────┐            │
│                                      │   Model    │            │
│                                      │  Storage   │            │
│                                      │ (pickle)   │            │
│                                      └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   ML INFERENCE PIPELINE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │
│  │ Input Data  │───▶│  Feature    │───▶│ Inference  │           │
│  │(PCAP/Zeek) │    │  Extraction│    │  (pickle) │           │
│  └─────────────┘    └─────────────┘    └──────┬──────┘           │
│                                              │                  │
│                       ┌────────────────────────┴─────┐             │
│                       ▼                            ▼             │
│               ┌─────────────┐             ┌─────────────┐            │
│               │  Anomaly    │             │  Attack    │            │
│               │   Score    │             │  Class     │            │
│               └────────────��┘             └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### 15.3 Features a Extraer

| Categoria | Features |
|-----------|-----------|
| Flujo | puertos origen/destino, bytes, duracion, paquetes |
| Temporal | tasa paquetes/seg, intervalos promedio |
| Comportamiento | patrones HTTP, DNS queries |
| Estadisticos | distribucion bytes por puerto |
| Red | protocols, flags TCP, tamanos de ventana |

### 15.4 Modelos Recomendados

| Tipo | Modelo | Uso |
|------|--------|-----|
| No supervisado | Isolation Forest | Deteccion de anomalias |
| No supervisado | One-Class SVM | Deteccion de anomalias |
| Supervisado | Random Forest | Clasificacion de ataques |
| Supervisado | XGBoost | Clasificacion de ataques |
| Secuencial | LSTM | Patrones temporales |

### 15.5 Modulos a Implementar

```python
class FeatureExtractor:
    """Extrae features de paquetes/sesiones."""

    def extract_flow_features(self, packets: list) -> dict:
        """Extrae features de flujo."""

    def extract_temporal_features(self, packets: list) -> dict:
        """Extrae features temporales."""

    def extract_statistical_features(self, packets: list) -> dict:
        """Extrae features estadisticos."""

    def to_vector(self, features: dict) -> np.array:
        """Convierte a vector numerico."""


class MLDetector:
    """Detector basado en ML."""

    def __init__(self, model_path: str = None):
        self.model = None
        self.load_model(model_path)

    def predict(self, features: np.array) -> tuple:
        """Predice (anomaly_score, attack_class)."""

    def predict_proba(self, features: np.array) -> dict:
        """Predice probabilidades."""


class MLTrainer:
    """Entrenamiento del modelo."""

    def prepare_dataset(self, pcap_files: list, labels: list) -> tuple:
        """Prepara dataset de entrenamiento."""

    def train(self, X: np.array, y: np.array):
        """Entrena el modelo."""

    def evaluate(self, X: np.array, y: np.array) -> dict:
        """Evalua el modelo."""

    def save_model(self, path: str):
        """Guarda el modelo."""
```

### 15.6 Dependencias ML

```txt
scikit-learn>=1.3
xgboost>=1.7
mlflow>=2.0
```

---

## 16. Live Capture + Machine Learning (Version Integrada)

### 16.1 Descripcion

Combina captura en tiempo real con deteccion basada en ML para obtener alertas en tiempo real con capacidades de deteccion de anomalias avanzadas.

### 16.2 Arquitectura Completa v3.0

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PCAP ANALYZER v3.0 (ML + Live)                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                       FASE: ENTRENAMIENTO                              │ │
│  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   │ │
│  │  │ Dataset   │──▶│  Feature  │──▶│   Train   │──▶│  Model    │   │ │
│  │  │ (labeled) │   │ Extract   │   │  (MLflow) │   │  Storage  │   │ │
│  │  └───────────┘   └───────────┘   └───────────┘   └───────────┘   │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                      │                                    │
│                                      ▼                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                    FASE: INFERENCIA (Live)                             │ │
│  │                                                                       │ │
│  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐        │ │
│  │  │  Sniffer  │──▶│  Buffer   │──▶│  Feature  │──▶│Inference │        │ │
│  │  │  (live)  │   │ Circular │   │ Extract  │   │ (pickle) │        │ │
│  │  └───────────┘   └───────────┘   └───────────┘   └─────┬─────┘        │ │
│  │                                                        │              │ │
│  │                         ┌──────────────────────────────┴──────┐       │ │
│  │                         ▼                                   ▼       ▼  │ │
│  │                  ┌─────────────┐                ┌────────────┐         │ │
│  │                  │  Anomaly    │──▶ score    │  Attack   │──▶class │ │
│  │                  │   Score    │            │  Class    │         │ │
│  │                  └─────────────┘                └────────────┘         │ │
│  │                         │                        │                      │ │
│  │                         ▼                        ▼                      │ │
│  │                  ┌─────────────┐          ┌─────────────┐         │ │
│  │                  │    LOW      │          │    HIGH    │         │ │
│  │                  │  (ignore)   │          │  (ALERT!)  │         │ │
│  │                  └─────────────┘          └─────────────┘         │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### 16.3 Flujo de Ejecucion

```
1. Captura:        sniff(count=1000, iface='eth0', store=False)
                      │
                      ▼
2. Buffer:        [paquetes] → CircularBuffer(max=5000)
                      │
                      ▼
3. Features:      buffer → extract_all_features() → [features]
                      │
                      ▼
4. Inference:    model.predict(features) → (anomaly_score, attack_class)
                      │
                      ├────────────────────────────┬───────────────────┐
                      ▼                        ▼                   ▼
               anomaly_score < 0.5        0.5-0.8          > 0.8
                  (正常)              (Monitoring)      (ALERT)
```

### 16.4 Umbrales y Acciones

| Score Anomalia | Accion | Descripcion |
|---------------|-------|-------------|
| 0.0 - 0.5 | Ignorar | Trafico normal |
| 0.5 - 0.7 | Monitorear | Posible anomalia, registrar |
| 0.7 - 0.85 | Warning | Alerta leve al SOC |
| 0.85 - 1.0 | Critical | Alerta critica al SOC |

### 16.5 Parametros de Configuracion

```env
# Live Capture
LIVE_MODE=true
INTERFACE=eth0
BUFFER_SIZE=5000
FLUSH_INTERVAL=5
BPF_FILTER=tcp

# ML
ML_MODEL_PATH=/path/to/model.pkl
ML_THRESHOLD=0.85
ML_CONFIDENCE_THRESHOLD=0.7
```

### 16.6 Comando Completo

```bash
python pcap_analyzer.py \
    --live \
    --iface eth0 \
    --ml-model /models/anomaly_detector.pkl \
    --ml-threshold 0.85 \
    --server-url https://soc-server:5000/log \
    --api-key secret
```

### 16.7 Checklist de Implementacion

- [ ] LiveCapture con scapy implementado
- [ ] CircularBuffer para streaming
- [ ] FeatureExtractor para ML
- [ ] MLDetector con modelo entrenado
- [ ] Integracion con SOC en tiempo real
- [ ] Pruebas en entorno controlado
- [ ] Documentacion actualizada

### 16.8 Version

| Version | Fecha | Cambios |
|---------|-------|----------|
| 4.0 | 2026-04-18 | Base de datos para ML |
| 3.0 | 2026-04-18 | Live Capture + ML integration |
| 2.0 | 2026-04-18 | Soporte PCAPNG y Zeek logs |
| 1.0 | 2026-04-18 | Version inicial |

### Mejoras a Largo Plazo

- Integracion con SIEM
- Analisis distribuido
- Deteccion basada en comportamientos

---

## Version History

| Version | Fecha | Cambios |
|---------|-------|----------|
| 4.0 | 2026-04-18 | Base de datos para ML |
| 3.0 | 2026-04-18 | Live Capture + ML integration |
| 2.0 | 2026-04-18 | Soporte PCAPNG y Zeek logs |
| 1.0 | 2026-04-18 | Version inicial |