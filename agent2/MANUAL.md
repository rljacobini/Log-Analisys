# Manual del Agente SOC

**Version:** 2.0

---

## 1. Resumen

El módulo de agentes SOC incluye:

| Script | Propósito | Logs | Estado |
|--------|-----------|------|-------|
| `agent/` | Monitoreo de logs de seguridad SSH | auth.log, iptables, suricata | ✅ Stable |
| `agent2/` | Agente para otro host | auth.log | ✅ Stable |
| `webagent/` | Monitoreo de logs web | Apache, Nginx access.log | 🚧 En desarrollo |

**Directorios:**
| Directorio | Propósito |
|------------|-----------|
| `agent/` | Agente principal (SSH) |
| `agent2/` | Copia para segundo host |
| `webagent/` | Agente web (Apache/Nginx) |

> **Nota:** `agent2/` es una copia de `agent/` para ejecutar múltiples agentes en paralelo.
> **Web agent:** El agente `webagent/` es independiente y no requiere `agent/agent.py`.

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[Manual del Servidor](../server/MANUAL.md)** - ServidorAPI
- 📄 **[Manual del Dashboard](../dashboard/MANUAL.md)** - Dashboard web
- 📄 **[Seguridad](../docs/Seguridad.md)** - Medidas de seguridad

---

## 2. Inicio Rapido

### Agente de Seguridad

```bash
cd agent
python agent.py
```

### Agente Web

```bash
cd agent
python web_agent.py
```

---

## 3. Configuracion

### Agente (agent.py)

Crear `.env` basado en `.env.example`:

```env
# Identificacion
AGENT_ID=server-01
AGENT_INTERVAL=10

# Servidor
SERVER_URL=https://servidor:5000/log
X_API_KEY=tu-clave
X_API_KEY_SECRET=

# Monitoreo
TARGET_HOST=192.168.1.1
TARGET_SERVICE=ssh
SOURCE=auth.log
LOG_FILE=/var/log/auth.log

# SSL
VERIFY_SSL=true
USE_SSL=true

# Batching
USE_BATCH_MODE=true
BATCH_SIZE=20
BATCH_TIMEOUT=30
```

### Web Agent (web_agent.py)

El web_agent.py monitorea logs de servidores web (Apache, Nginx) para detectar ataques aplicaciones web.

**Características:**
- Detecta SQL Injection, XSS, Path Traversal, Command Injection
- Detección de scanners de seguridad (nmap, sqlmap, etc.)
- Detección de HTTP Flood
- Detección de enumeración 404
- Detección de intentos de upload de archivos

**Ejecución:**
```bash
cd agent
python web_agent.py
```

**Crear `.env` basado en `web_agent.env.example`:**
```env
# Identificacion
WEB_AGENT_ID=web-srv-01
WEB_TARGET_HOST=192.168.1.20
WEB_TARGET_SERVICE=http
WEB_SOURCE=apache

# Archivo de log
WEB_LOG_FILE=data/web_access.log

# Servidor
WEB_SERVER_URL=https://servidor:5000/log
WEB_BATCH_URL=https://servidor:5000/log/batch
WEB_API_KEY=tu-clave
WEB_API_SECRET=

# Opciones
WEB_USE_SSL=true
WEB_VERIFY_SSL=false
WEB_USE_BATCH_MODE=true
WEB_BATCH_SIZE=20
WEB_BATCH_TIMEOUT=30

# Deteccion
WEB_FLOOD_THRESHOLD=100
WEB_FLOOD_WINDOW=60
WEB_SUSPICIOUS_404_THRESHOLD=10
WEB_SUSPICIOUS_404_WINDOW=300
```

---

## 4. Fuentes de Log

### Agente de Seguridad

| Fuente | Logs | Patrones Detectados |
|--------|------|---------------------|
| auth.log | SSH | brute_force, sudo_failure, ssh_login |
| iptables | Firewall | iptables_blocked, iptables_drop |
| suricata | IDS | ids_alert, ids_stream |

### Web Agent

| Fuente | Formato | Ataques Detectados |
|--------|---------|-------------------|
| Apache access.log | Combined | sqli, xss, path_traversal, command_injection, scanner |
| Apache error.log | Apache | server errors, file upload |
| Nginx access.log | Combined | Todos los anteriores |

**Patrones de detección (patterns/web.py):**
| Patrón | Riesgo | Descripción |
|-------|--------|-------------|
| SQL keywords (union, select, drop...) | 35 | SQL Injection |
| `<script`, `javascript:` | 30 | XSS |
| `../`, `..%2e` | 40 | Path Traversal |
| `;`, `\|`, `&&`, `$()` | 45 | Command Injection |
| User-Agent: sqlmap, nmap, nikto | 25 | Security Scanner |
| POST a /upload, /save | 35 | File Upload |

---

## 5. Arquitectura

### Clase Base AgentBase

Ambos agentes heredan de `AgentBase` que proporciona:

```python
class AgentBase:
    # Persistencia de estado
    # Envio de eventos (sync/async)
    # Batching con configuracion
    # Retry con exponential backoff
    # Deduplicacion por hash
    # Logging estructurado
    # Request signing (HMAC)
    # Nonce anti-replay
```

---

## 6. Eventos Generados

### Agente de Seguridad

| Tipo | Riesgo | Descripcion |
|------|--------|-------------|
| brute_force_start | 5-25 | Inicio de ataque |
| brute_force_ongoing | 30 | Ataque continuado |
| brute_force_end | -5 | Fin del ataque |
| ssh_login_success | 25 | Login exitoso |
| sudo_failure | 15 | Fallo de sudo |
| ids_alert | 20 | Alerta de IDS |

### Web Agent

| Tipo | Riesgo | Descripcion |
|------|--------|-------------|
| sqli_attempt | 35 | SQL Injection |
| xss_attempt | 30 | Cross-Site Scripting |
| path_traversal | 40 | Path traversal |
| command_injection | 45 | Command injection |
| scanner_detection | 25 | Security scanner |
| http_flood_start | 25 | HTTP flood |
| 404_enumeration | 10 | Enumeracion 404 |
| file_upload_attempt | 35 | Intento de upload |

---

## 7. Seguridad de Comunicaciones

### Request Signing (Recomendado)

Para produccion, configurar HMAC-SHA256:

1. **Generar secret en servidor:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

2. **En servidor (server/.env):**
```env
AGENT_API_SECRET=<secret>
```

3. **En agente:**
```env
X_API_KEY_SECRET=<mismo-secret>
```

### Headers de Seguridad

```
X-API-Key: <clave>
X-Request-ID: <nonce>
X-Request-Timestamp: <unix>
X-Request-Signature: <hmac>
```

### Protecciones Implementadas

| Capa | Proteccion |
|------|-----------|
| Autenticacion | X-API-Key |
| Integridad | HMAC-SHA256 |
| Anti-Replay | Nonce + Timestamp |
| Validacion | Type checking |
| Sanitizacion | Caracteres peligrosos bloqueados |

### Caracteres Bloqueados

```
Nueva linea: \r, \n
Shell: ; & | ` $ ( ) { } < > \
Path: ../ %2e%2e
```

---

## 8. Sistema de Riesgo

### Niveles de Riesgo

El agente clasifica los eventos en 5 niveles de riesgo:

| Nivel | Rango | Descripcion | Accion |
|-------|-------|-------------|--------|
| **LOW** | 0-14 | Eventos de bajo impacto | Loggear |
| **MEDIUM** | 15-29 | Eventos de riesgo moderado | Loggear + alerta si configurado |
| **HIGH** | 30-49 | Eventos de alto riesgo | Alerta inmediata |
| **CRITICAL** | 50-99 | Eventos criticos | Alerta urgente |
| **BREACH** | 100+ | Brecha de seguridad confirmada | Alerta critica + acciones automaticas |

### Correlacion de Eventos

El agente implementa evaluacion de riesgo segun NIST SP 800-53 y MITRE ATT&CK:

| Contexto | Riesgo | Severidad |
|----------|--------|-----------|
| Login sin precedentes | 20 | INFO |
| Login con intentos fallidos (1-3) | 30-40 | MEDIUM |
| Login con intentos >3 | 50-80 | HIGH |
| Login exitoso despues de brute force | 70-100 | CRITICAL |
| Brute force en curso | 80 | HIGH |
| Cuenta comprometida (brecha) | 100+ | BREACH |

> **Nota:** El nivel BREACH se asigna cuando se confirma que un atacante ha obtenido acceso exitoso al sistema. |

---

## 9. Modo Batching

Reduce carga en servidor agrupando eventos:

```env
USE_BATCH_MODE=true
BATCH_SIZE=20
BATCH_TIMEOUT=30
```

**Ventajas:**
- Menor uso de red
- Mejor rendimiento
- Retry automatico en batch

---

## 10. Multiples Agentes

La plataforma soporta multiples agentes simultaneos.

### Reglas

1. **AGENT_ID unico** - Cada agente diferente
2. **X_API_KEY compartida** - Misma clave en servidor
3. **STATE_DIR separado** - Carpetas de estado distintas
4. **LOG_FILE diferente** - Archivos de log distintos

### Como Ejecutar Múltiples Agentes

#### Opcion 1: Copiar directorio completo

```powershell
# 1. Copiar el directorio agent
copy -r agent agent2

# 2. Editar agent2/.env
AGENT_ID=agent-srv-02
TARGET_HOST=192.168.1.20

# 3. Crear run_agent2
copy run_agent run_agent2
# Editar run_agent2: cambiar "from agent.agent" a "from agent2.agent"

# 4. Ejecutar en terminales separadas
python run_agent      # Agente 1
python run_agent2     # Agente 2
```

#### Opcion 2: Cambiar .env temporalmente

```powershell
# 1. Respaldar configuracion actual
copy agent\.env agent\.env.backup

# 2. Editar .env con nuevo AGENT_ID
# (cambiar AGENT_ID, TARGET_HOST, etc.)

# 3. Ejecutar en otra terminal
python run_agent

# 4. Restaurar configuracion original
copy agent\.env.backup agent\.env
```

### Estructura Recomendada

```
soc-platform/
├── run_agent
├── run_agent2
├── agent/
│   ├── agent.py
│   ├── web_agent.py
│   ├── .env
│   └── agent-srv-01_state.json
└── agent2/
    ├── agent.py
    ├── web_agent.py
    ├── .env
    └── agent-srv-02_state.json
```

---

## 11. Estado

El agente guarda estado en archivo JSON:
- Posicion en archivo de log
- Hash de logs procesados
- Estadisticas
- Ataques activos

**Ubicacion:** `{AGENT_ID}_state.json` en `STATE_DIR`

### Reiniciar Estado

```bash
# Detener agente
# Eliminar archivo de estado
del agent-01_state.json
# Reiniciar agente
```

---

## 12. Variables de Configuracion

### Identificacion

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `AGENT_ID` | Identificador unico del agente | hostname |
| `TARGET_HOST` | IP del host que monitorea | IP local |
| `TARGET_SERVICE` | Servicio (ssh, http, ftp) | ssh |
| `SOURCE` | Tipo de log (auth.log, secure) | auth.log |

### Conexion al Servidor

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `SERVER_URL` | URL del servidor SOC | https://127.0.0.1:5000/log |
| `BATCH_URL` | URL para modo batch | derivation de SERVER_URL |
| `USE_SSL` | Habilitar HTTPS | true |
| `VERIFY_SSL` | Verificar certificado | true |
| `X_API_KEY` | Clave API (requerida) | - |
| `X_API_KEY_SECRET` | Secret para HMAC (opcional) | - |

### Deteccion

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `BRUTE_FORCE_THRESHOLD` | Intentos para detectar brute force | 5 |
| `BRUTE_FORCE_WINDOW` | Ventana de tiempo (segundos) | 60 |
| `RISK_CRITICAL` | Umbral riesgo critico | 50 |
| `RISK_HIGH` | Umbral riesgo alto | 30 |
| `RISK_MEDIUM` | Umbral riesgo medio | 15 |

### Cooldown

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `SEND_COOLDOWN_DEFAULT` | Segundos entre alertas | 15 |
| `SEND_COOLDOWN_CRITICAL` | Cooldown critico | 0 |
| `SEND_COOLDOWN_HIGH` | Cooldown alto | 5 |

### Batch Mode

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `USE_BATCH_MODE` | Habilitar batching | true |
| `BATCH_SIZE` | Eventos por batch | 20 |
| `BATCH_TIMEOUT` | Timeout de flush (segundos) | 30 |
| `BATCH_RETRY_QUEUE_SIZE` | Tamano de cola de retry | 100 |
| `MAX_BATCH_RETRIES` | Maximo reintentos | 3 |
| `INITIAL_RETRY_DELAY` | Delay inicial (segundos) | 5 |
| `MAX_RETRY_DELAY` | Delay maximo (segundos) | 120 |

### Persistencia

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `STATE_DIR` | Directorio de estado | carpeta del agente |
| `LOG_FILE` | Archivo de log a monitorear | data/auth.log |

### Certificate Pinning

**Que es?**
Proteccion adicional contra ataques MITM. Especificas el fingerprint del certificado esperado.

**Como obtener el fingerprint:**
```bash
openssl x509 -in server.crt -fingerprint -sha256
```

**Como configurarlo:**
```env
CERT_PINS=sha256=AB:CD:EF:12:34:56:78:...
```

**Cuando usarlo:**
- Desarrollo: No necesario
- Produccion: Opcional

---

## 13. Troubleshooting

| Error | Solucion |
|-------|----------|
| Archivo no encontrado | Verificar LOG_FILE y permisos |
| Server not reachable | Verificar SERVER_URL y API Key |
| SSL verification failed | VERIFY_SSL=false (desarrollo) |
| Rate limited | Reducir BATCH_SIZE o AGENT_INTERVAL |
| 401 Unauthorized | Verificar X_API_KEY |

---

## 13. Modulos

| Modulo | Descripcion |
|-------|-------------|
| `config.py` | Configuracion |
| `security.py` | Sanitizacion de datos |
| `persistence.py` | Persistencia de estado |
| `base.py` | Clase AgentBase |
| `patterns/` | Patrones de deteccion |
| `patterns/auth.py` | Patrones SSH/iptables |
| `patterns/web.py` | Patrones Apache/Nginx |

---

## Version History

| Version | Fecha | Cambios |
|---------|-------|----------|
| 1.0 | 2026-04-16 | Version inicial |
| 2.0 | 2026-04-18 | Unificado agente y web agent |