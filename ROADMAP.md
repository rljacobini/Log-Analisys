# ROADMAP - Evolución del SOC Platform
> **Nota:** Este documento NO se subirá a GitHub. Es para desarrollo interno.

---

## 1. Migración a FastAPI

### Estado Actual (Flask)
- Server Flask en puerto 5000
- Agentes con requests HTTP
- Dashboard Flask en puerto 8000

### Beneficios de FastAPI
- Validación automática de tipos (Pydantic)
- Documentación OpenAPI automática (`/docs`)
- Rendimiento async mejorado
- WebSocket nativo
- Mejor handling de concurrencia

### Pasos a Seguir
1. Crear modelos Pydantic para eventos
2. Migrar endpoints del server uno por uno
3. Mantener compatibilidad con agentes Flask (fallback)
4. Tests de carga
5. Implementar WebSocket para alertas en tiempo real

### Endpoints Actuales (Flask)
```
POST /log         - Recibe eventos
POST /log/batch   - Recibe eventos en batch
GET  /agents      - Lista agentes
GET  /stats      - Estadísticas
GET  /logs       - Lista logs
GET  /health     - Health check
GET  /metrics    - Métricas
```

### Endpoints Propuestos (FastAPI)
```
POST /api/v1/log          - Recibe eventos
POST /api/v1/log/batch    - Batch
GET  /api/v1/agents       - Lista agentes
GET  /api/v1/stats        - Estadísticas
GET  /api/v1/logs         - Lista logs
GET  /api/v1/logs/{id}    - Detalle de log
WS   /ws/alerts            - WebSocket para alertas
GET  /api/v1/health       - Health check
GET  /api/v1/metrics     - Métricas Prometheus
```

---

## 2. Mejoras en PCAP Analyzer

### Detecciones Actuales (31 métodos)
| Categoría | Detecciones |
|-----------|-------------|
| **Scans** | port_scan, host_discovery |
| **DoS/DDoS** | syn_flood, icmp_flood, udp_flood, dos_attacks, ddos |
| **Brute Force** | ssh_brute_force, ftp_brute_force, http_brute_force |
| **Spoofing** | arp_spoofing, mac_spoofing, tcp_hijacking, ssl_strip, dns_spoofing, dns_poisoning |
| **Exfiltración** | data_exfiltration, dns_tunneling |
| **C2** | c2_traffic, c2_behavior, suspicious_downloads |
| **Malware** | malware_iocs, malware_downloads, cryptojacking |
| **Web** | web_attacks, api_abuse |
| **Credenciales** | cleartext_credentials |
| **Anomalías** | network_anomaly, enumeration |

### Detecciones Faltantes (Propuestas)
| Deteccion | Prioridad | Descripcion |
|-----------|---------|-----------|
| **TLS fingerprinting** | Alta | Detectar versiones antiguas/suite debil |
| **Heartbleed** | Alta | Detectar traffic hacia puerto 443 con patron especifico |
| **Shellshock** | Alta | Detectar user-agent con () { } |
| **ZeroLogon** | Media | Detectar conexiones SMB con zeros |
| **SMB exploits** | Media | Detectar versiones SMBv1 antiguas |
| **VPN tunneling** | Media | Detectar trafico a puertos VPN no comunes |
| **IRC Bot** | Media | Detectar traffic a puertos IRC (6667, 6697) |
| **Tor traffic** | Media | Detectar conexiones a Exit Nodes |
| **BEC (Business Email)** | Baja | Detectar patrones de CEO fraud |
| **TLS 1.3 downgrade** | Baja | Detectar intentos de downgrade |
| **Quic protocol** | Baja | Detectar trafico QUIC experimental |
| **Wireguard** | Baja | Detectar puertos WireGuard (512, 51820) |
| **Covert channels** | Baja | Detectar timing channels |
| **Protocol confusion** | Baja | Detectar HTTP sobre DNS |

### Mejoras Técnicas PCAP
- Paralelización con multiprocessing
- Machine Learning para anomalías ( Isolation Forest )
- Integración con STIX/TAXII
- SoporteZeek 7.0+
- Indexación de sesiones en Redis

---

## 3. Web Agent - Pruebas Reales

### Estado Actual
- Código completo con detección de ataques web
- Patrones para Apache/Nginx
- Correlación de eventos
- Persistencia de estado

### Pruebas Reales Necesarias
1. **Logs reales Apache/Nginx** - Obtener acceso.log de producción (anonimizado)
2. **WAF logs** - Integrar con ModSecurity
3. **Load testing** - Simular ataques con siege/wrk
4. **Correlación con agent/** - Detectar ataques que vienen por SSH y web
5. **Docker testing** - Contenedor con Apache + logs simulados

### Scripts de Prueba Propuestos
```
pcap/test_web_agent.py      - Test con logs simulados
pcap/test_real_traffic.py  - Test con tcpdump real
```

---

## 4. Correlación de Eventos

### Estado Actual
- `correlate_login_after_bruteforce()` - Login exitoso post brute force
- `_check_correlation()` en web_agent - Correlación básica
- `re_correlate_all_threats()` - Re-correlación periódica

### Correlación Faltante
| Tipo | Descripcion | Prioridad |
|------|-----------|---------|
| **Ataque distribuido** | Misma IP atacando multiples hosts | Alta |
| **Campaign** | Mismo ataque en ventana de tiempo | Alta |
| **Lateral movement** | SSH desde IP comprometida | Alta |
| **Data exfil chain** | Download + DNS tunneling + C2 | Media |
| **Privilege escalation** | Usuario normal luego admin | Media |
| **Port scan + exploit** | Scan seguido de intento de exploit | Media |
| **Web + SSH** | Misma IP atacando web y SSH | Media |
| **Recon + attack** | Enumeración seguida de ataque | Baja |
| **C2 beaconing** | Tráfico periódico a mismo destino | Baja |
| **Fileless malware** | PowerShell sin archivo | Baja |

### Algoritmos Propuestos
- Graph-based correlation (NetworkX)
- Time windows con sliding
- ML clustering para campaigns
- Threat intel matching

---

## 5. Arquitectura Alternativa: Agente Ligero

### Concepto
Agentes que solo recolectan y envían logs al servidor. El análisis se hace en paralelo en el servidor.

### Beneficios
- Agentes minimalistas (menor superficie de ataque)
- Análisis centralizado y configurable
- Fácil de actualizar regras
- Menor consumo de recursos en endpoints

### Arquitectura Propuesta
```
Endpoint                    Server                    Analysis
   |                         |                        |
   |-- syslog/log file -----> | -- Raw Storage --> | -- Async Analysis
   |                         |                | -- ML Engine
   |                         |                | -- Correlation
   |                         |                | -- Threat Intel
   |                         |                        |
   |<------ Alerts <-------- | <-- Results <-- |
```

### Base de Datos Alternativas
| DB | Caso de Uso |
|----|-----------|
| **TimescaleDB** | Series temporales, compresión |
| **ClickHouse** | Analytics massivo, SQL |
| **Elasticsearch** | Búsqueda, Kibana |
| **Timescale + ES** | Lo mejor de ambos |

---

## 6. Prioridades

### Fase 1 (Inmediato)
1. [ ] Pruebas reales web_agent
2. [ ] Migrar server a FastAPI (endpoint por endpoint)
3. [ ] Añadir detecciones TLS fingerprinting, Heartbleed

### Fase 2 (Corto plazo)
1. [ ] WebSocket para alertas en tiempo real
2. [ ] Correlación distribuida
3. [ ] Machine Learning para anomalías

### Fase 3 (Largo plazo)
1. [ ] Arquitectura agente ligero opcional
2. [ ] TimescaleDB como alternativa
3. [ ] STIX/TAXII integration

---

## 8. Sistema de CVE (Common Vulnerabilities and Exposures)

### Estado Actual
- No hay integración con CVEs en el sistema
- Las detecciones PCAP solo muestran attack_type y severity

### Objetivos
- Enriquecer eventos con información de CVEs
- Detectar servicios vulnerables
- Alertar sobre vulnerabilidades conocidas

---

### Temas de CVE a Implementar

#### Tema 1: CVE Lookup por Puerto (Fácil)
Mapear puertos comunes a CVEs conocidos:
```python
CVE_PORT_MAP = {
    22: ["CVE-2023-XXXXX"],   # SSH
    80: ["CVE-2024-XXXXX"],   # Apache
    443: ["CVE-2024-XXXXX"],  # OpenSSL
    445: ["CVE-2017-0143"],    # EternalBlue (SMB)
    3389: ["CVE-2019-0708"],  # BlueKeep (RDP)
    3306: ["CVE-2022-XXXXX"], # MySQL
    5432: ["CVE-2021-XXXXX"], # PostgreSQL
    6379: ["CVE-2020-XXXXX"], # Redis
    27017: ["CVE-2021-XXXXX"], # MongoDB
}
```

#### Tema 2: CVE Alerting (Fácil)
Alertas cuando se detecta servicio vulnerable:
- Cuando se detecta tráfico a puerto conocido vulnerable
- Mostrar CVEs asociados en la alerta
- Alertar si hay exploit activo

#### Tema 3: CVSS Score Display (Fácil)
Mostrar score CVSS en alertas:
- CRITICAL: 9.0-10.0
- HIGH: 7.0-8.9
- MEDIUM: 4.0-6.9
- LOW: 0.1-3.9

#### Tema 4: CVE Reporting (Fácil)
Generar reportes de CVEs detectados:
- Resumen de CVEs por severidad
- Timeline de detecciones
- Exportar a PDF/CSV

#### Tema 5: NVD API Integration (Medio)
Consultar API de NVD para obtener CVEs:
```
https://services.nvd.nist.gov/rest/json/cves/2.0?keyword=apache
```

#### Tema 6: CVE Database Local (Medio)
DB local con top CVEs actualizable:
- Top 100 CVEs del año
- Actualización periódica
- Búsqueda offline

#### Tema 7: Version Detection + CVE (Medio)
Detectar versión de servicio desde PCAP y buscar CVEs:
- Extraer banner de servicio
- Comparar con versiones vulnerables
- Mostrar CVEs aplicables

#### Tema 8: CVE Correlation con IDS (Medio)
Correlacionar alertas Suricata con DB de CVEs:
- Detectar attack type
- Mapear a CVEs conocidos
- Score de explotación

#### Tema 9: CVE Enrichment (Medio)
Enriquecer eventos con datos de CVE de fuentes externas:
- NVD
- VulnDB
- SecurityFocus

#### Tema 10: CVE Threat Intel (Medio)
Feed de inteligencia de CVE:
- CISA KEV
- Exploit-DB
- Metasploit modules

#### Tema 11: CVE Coverage Analysis (Medio)
Analizar qué CVEs cubre nuestra detección:
- Mapping ataque → CVE
- Porcentaje de cobertura
- Gaps identificados

#### Tema 12: CVE Timeline (Medio)
Mostrar línea de tiempo de divulgación:
- Cuándo se publicó el CVE
- Cuándo se publicó exploit
- Tendencias

---

### Diseño Propuesto

#### Base de Datos
```sql
CREATE TABLE cve_database (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE,
    description TEXT,
    cvss_score FLOAT,
    severity VARCHAR(20),
    affected_products JSON,
    published_date DATE,
    exploit_available BOOLEAN,
    port_mapping JSON
);
```

#### API Endpoints
```
GET /api/v1/cve/search?keyword=apache
GET /api/v1/cve/port/445
GET /api/v1/cve/stats
POST /api/v1/cve/update  (admin)
```

#### Dashboard
- Panel de CVEs detectados
- Stats por severidad
- Timeline
- Exportar IOC

---

### Herramientas y APIs
| Recurso | URL |
|---------|-----|
| NVD API | https://nvd.nist.gov/developers/vulnerabilities |
| CVE.org | https://www.cve.org/ |
| MITRE CVE | https://cve.mitre.org/ |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Exploit-DB | https://www.exploit-db.com/ |
| CVSS Calculator | https://nvd.nist.gov/vuln-metrics/cvss |

---

## 7. Análisis Forense de Detecciones PCAP

### Estado Actual
- Dashboard muestra tabla de detecciones con paginación
- Gráficos de severidad y tipo de ataque
- Stats: total, CRITICAL, HIGH, MEDIUM, LOW, INFO

### Propuesta: Detalle de Evento con Análisis Forense

#### Objetivo
Permitir análisis detallado de cada detección para investigación forense, con contexto educativo y acciones recomendadas.

#### Características Propuestas

**1. Página de Detalle por Evento**
- Todos los campos del evento expandidos
- Explicaciones de términos técnicos
- Contextualización del ataque

**2. Información Enrichecida**
- Geolocalización de IPs (Country, City, ISP)
- Reputación IP (AbuseIPDB)
- WHOIS del dominio/IP destino
- Relación con IOC conocidos

**3. Información Educativa**
- Qué es el ataque detectado
- Cómo funciona la técnica MITRE asociada
- Pasos de remediación recomendados
- Links a documentación de referencia

**4. Timeline Visual**
- Ver eventos relacionados por IP
- Ver todos los eventos de la misma sesión

**5. Exportar Evidencia**
- PDF del análisis completo
- IOC list para SIEM/EDR

#### Diseño Propuesto
```
┌─────────────────────────────────────────────────────────────┐
│  Evento #1234 - suspicious_download                        │
├─────────────────────────────────────────────────────────────┤
│  IP Origen: 10.12.19.101  →  IP Destino: 185.141.25.68  │
│  Severidad: CRITICAL  Risk: 75  Puerto: 80                │
│                                                             │
│  ┌─ Contexto ──────────────────────────────────────────┐   │
│  │ Este equipo ha descargado archivos de servidores    │   │
│  │ externos de forma sospechosa. posible malware.     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─ Información de Red ────────────────────────────────┐    │
│  │ Geolocalización: NL (Países Bajos)                │    │
│  │ ISP:leaseweb   AbuseIPDB: 85% malicious          │    │
│  │ Técnica MITRE: T1105 - Ingress Tool Transfer      │    │
│  └───────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─ Acciones Recomendadas ───────────────────────────┐     │
│  │ 1. Aislar equipo de la red                      │     │
│  │ 2. Análisis de memoria/disco                    │     │
│  │ 3. Revisar procesos sospechosos                 │     │
│  │ 4. Buscar beacons C2                            │     │
│  └───────────────────────────────────────────────────┘     │
│                                                             │
│  [Exportar PDF]  [Exportar IOC]  [Ver Timeline]          │
└─────────────────────────────────────────────────────────────┘
```

#### Campos a Mostrar
| Campo | Descripción | Enriquecido |
|-------|-------------|-------------|
| event_id | ID único | - |
| timestamp | Cuándo ocurrió | Formato local |
| src_ip | IP origen | Geo + Reputación |
| dst_ip | IP destino | Geo + WHOIS |
| attack_type | Tipo de ataque | Explicación |
| severity | CRITICAL/HIGH/etc | Qué significa |
| risk | Score 0-100 | Indicador visual |
| MITRE technique | ID técnica | Descripción + mitigación |
| extra_data.evidence | Evidencia cruda | Pretty print |
| extra_data.indicators | IOCs | Links a VirusTotal |

#### Links de Referencia
- MITRE ATT&CK: https://attack.mitre.org/
- CAPEC: https://capec.mitre.org/
- NIST: https://csrc.nist.gov/

---

## 8. Referencias

- FastAPI: https://fastapi.tiangolo.com/
- Pydantic: https://docs.pydantic.dev/
- Zeek: https://zeek.org/
- STIX: https://oasis-open.github.io/stix-specification/
- TimescaleDB: https://www.timescale.com/
- MITRE ATT&CK: https://attack.mitre.org/

---

*Última actualización: 2026-04-21*