# Manual del Agente Web (WebAgent)

**Version:** 2.0

---

## 1. Resumen

El **WebAgent** es un agente especializado para el monitoreo de logs de servidores web (Apache, Nginx). Detecta ataques a aplicaciones web en tiempo real.

| Script | Propósito | Logs | Estado |
|--------|-----------|------|--------|
| `agent/` | Monitoreo de logs SSH | auth.log, iptables, suricata | ✅ Stable |
| `agent2/` | Segundo agente SSH | auth.log | ✅ Stable |
| `webagent/` | Monitoreo de logs web | Apache, Nginx access.log | ✅ Stable |

**Directorios:**
| Directorio | Propósito |
|------------|-----------|
| `agent/` | Agente principal (SSH) |
| `agent2/` | Copia para segundo host |
| `webagent/` | Agente web (Apache/Nginx) |

> **Nota:** El WebAgent es independiente y no comparte código con los agentes de seguridad.

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[Manual del Agente](../agent/MANUAL.md)** - Agente de seguridad SSH
- 📄 **[Manual del Servidor](../server/MANUAL.md)** - Servidor API
- 📄 **[Manual del Dashboard](../dashboard/MANUAL.md)** - Dashboard web

---

## 2. Inicio Rápido

```bash
cd webagent
python web_agent.py
```

### Prerrequisitos

1. Python 3.8+
2. Archivo `.env` configurado
3. Archivo de log accesible

---

## 3. Configuración

### Crear `.env` basado en `.env.example`:

```env
# Identificación
WEB_AGENT_ID=web-srv-01
WEB_AGENT_INTERVAL=10

# Servidor
WEB_SERVER_URL=https://servidor:5000/log
WEB_BATCH_URL=https://servidor:5000/log/batch
WEB_API_KEY=tu-clave
WEB_API_SECRET=

# Monitoreo
WEB_TARGET_HOST=192.168.1.20
WEB_TARGET_SERVICE=http
WEB_SOURCE=apache
WEB_LOG_FILE=data/web_access.log

# SSL
WEB_VERIFY_SSL=false
WEB_USE_SSL=true

# Batching
WEB_USE_BATCH_MODE=true
WEB_BATCH_SIZE=20
WEB_BATCH_TIMEOUT=30
```

---

## 4. Fuentes de Log

### Formatos Soportados

| Formato | Descripción | Variables Extraídas |
|---------|-------------|---------------------|
| Apache Access Log | Combined Log Format | ip, method, path, status, bytes, referer, user_agent |
| Nginx Access Log | Combined Log Format | ip, method, path, status, bytes, referer, user_agent |
| Apache Error Log | Error Log Format | timestamp, level, message, pid |

### Configuración de Log del Servidor

**Apache (httpd.conf o apache2.conf):**
```
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
CustomLog logs/access_log combined
```

**Nginx (nginx.conf):**
```
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log main;
```

---

## 5. Patrones de Detección

El WebAgent detecta los siguientes ataques:

| Patrón | Riesgo | Descripción | Ejemplo |
|--------|--------|-------------|---------|
| **SQL Injection** | 35 | Inyección SQL | `union select * from users` |
| **XSS** | 30 | Cross-Site Scripting | `<script>alert(1)</script>` |
| **Path Traversal** | 40 | Acceso a archivos sensibles | `../../etc/passwd` |
| **Command Injection** | 45 | Ejecución de comandos | `; cat /etc/passwd` |
| **Scanner Detection** | 25 | Escáneres de seguridad | sqlmap, nmap, nikto |
| **File Upload** | 35 | Subida de archivos | `/upload.php` |
| **LDAP Injection** | 30 | Inyección LDAP | `*)(uid=*))(|(uid=` |
| **XML Injection** | 25 | Inyección XML | `<!DOCTYPE>` |
| **CSRF Attempt** | 15 | Manipulación de tokens | `csrf=` |
| **HTTP Flood** | 20-40 | Denegación de servicio | Múltiples requests |
| **404 Enumeration** | 10 | Exploración de directorios | Múltiplos 404 |
| **Error 403** | 10 | Acceso prohibido | Acceso denegado |
| **Error 500** | 15 | Error del servidor | Error interno |

### Detalles de Patrones

**SQL Injection:**
- Keywords: `union`, `select`, `insert`, `update`, `delete`, `drop`, `exec`, `execute`, `script`, `--`, `;`, `@@version`

**XSS:**
- Tags: `<script>`, `<img>`, `<svg>`, `<iframe>`
- Events: `onerror=`, `onload=`
- Protocols: `javascript:`

**Path Traversal:**
- Patterns: `../`, `..\`
- Files: `/etc/passwd`, `/etc/shadow`, `c:\windows`

**Command Injection:**
- Separators: `;`, `|`, `&`, `` ` ``, `$`, `\`

**Security Scanners:**
- Tools: nmap, sqlmap, nikto, gobuster, dirb, wfuzz, burp, metasploit, acunetix, Nessus

---

## 6. Arquitectura

### Clase WebAgent

```
WebAgent (hereda de AgentBase)
├── monitor()              - Loop principal de monitoreo
├── _parse_log_line()      - Parsea Apache/Nginx logs
├── _check_injection_patterns() - Detecta ataques
├── _is_http_flood()       - Detecta flood
├── _handle_*()            - Manejadores por tipo de ataque
├── _check_correlation()  - Correlación de eventos
└── _should_send()        - Control de cooldown
```

### Características Avanzadas

- **Cooldown:** Evita alertas duplicadas
- **Correlación de Eventos:** Detecta ataque después de scanner
- **HTTP Flood Detection:** Monitorea tasa de requests
- **404 Enumeration:** Detecta exploración de directorios
- **Persistencia de Estado:** Guarda posición en log y ataques activos

---

## 7. Sistema de Riesgo

### Niveles de Riesgo

| Nivel | Rango | Descripción |
|-------|-------|-------------|
| **LOW** | 0-14 | Eventos de bajo impacto |
| **MEDIUM** | 15-29 | Eventos de riesgo moderado |
| **HIGH** | 30-49 | Eventos de alto riesgo |
| **CRITICAL** | 50-99 | Eventos críticos |

### Riesgo por Correlación

El riesgo base se incrementa cuando se detecta correlación:

| Contexto | Modificador | Severidad |
|----------|-------------|-----------|
| Scanner detectado | +20 | MEDIUM → HIGH |
| Múltiples ataques (≥5) | +20 | Incremento progresivo |
| Scanner + Ataque | +20 | Escalación automática |

### Cooldowns

| Severidad | Cooldown (segundos) |
|-----------|---------------------|
| CRITICAL | 0 |
| HIGH | 15 |
| MEDIUM | 30 |
| DEFAULT | 30 |

---

## 8. Eventos Generados

| Evento | Riesgo Base | Descripción |
|--------|-------------|-------------|
| `sqli_attempt` | 35 | SQL Injection |
| `xss_attempt` | 30 | Cross-Site Scripting |
| `path_traversal` | 40 | Path traversal |
| `command_injection` | 45 | Command injection |
| `scanner_detection` | 25 | Escáner de seguridad |
| `http_flood_start` | 25 | Inicio de flood |
| `http_flood_end` | -5 | Fin de flood |
| `404_enumeration` | 10 | Enumeración 404 |
| `file_upload_attempt` | 35 | Intento de upload |
| `error_403` | 10 | Acceso prohibido |
| `error_500` | 15 | Error del servidor |
| `ldap_injection` | 30 | LDAP Injection |
| `xml_injection` | 25 | XML Injection |
| `csrf_attempt` | 15 | CSRF attempt |

---

## 9. Modo Batching

Reduce carga en servidor agrupando eventos:

```env
WEB_USE_BATCH_MODE=true
WEB_BATCH_SIZE=20
WEB_BATCH_TIMEOUT=30
```

**Ventajas:**
- Menor uso de red
- Mejor rendimiento
- Retry automático en batch

---

## 10. Variables de Configuración

### Identificación

| Variable | Descripción | Default |
|----------|-------------|---------|
| `WEB_AGENT_ID` | Identificador único | web-agent-01 |
| `WEB_TARGET_HOST` | IP del host monitoreado | 0.0.0.0 |
| `WEB_TARGET_SERVICE` | Servicio | http |
| `WEB_SOURCE` | Tipo (apache, nginx) | apache |

### Conexión al Servidor

| Variable | Descripción | Default |
|----------|-------------|---------|
| `WEB_SERVER_URL` | URL del servidor SOC | https://127.0.0.1:5000/log |
| `WEB_BATCH_URL` | URL para modo batch | derivación de SERVER_URL |
| `WEB_USE_SSL` | Habilitar HTTPS | true |
| `WEB_VERIFY_SSL` | Verificar certificado | true |
| `WEB_API_KEY` | Clave API (requerida) | - |
| `WEB_API_SECRET` | Secret para HMAC | - |

### Monitoreo

| Variable | Descripción | Default |
|----------|-------------|---------|
| `WEB_LOG_FILE` | Archivo de log | requerido |
| `WEB_AGENT_INTERVAL` | Intervalo (segundos) | 10 |
| `WEB_REQUEST_TIMEOUT` | Timeout request | 10 |

### Detección

| Variable | Descripción | Default |
|----------|-------------|---------|
| `WEB_FLOOD_THRESHOLD` | Requests para flood | 100 |
| `WEB_FLOOD_WINDOW` | Ventana de tiempo (seg) | 60 |
| `WEB_SUSPICIOUS_404_THRESHOLD` | 404s para alerta | 10 |
| `WEB_SUSPICIOUS_404_WINDOW` | Ventana 404 (seg) | 300 |

### Cooldown

| Variable | Descripción | Default |
|----------|-------------|---------|
| `WEB_SEND_COOLDOWN_DEFAULT` | Segundos entre alertas | 30 |
| `WEB_SEND_COOLDOWN_CRITICAL` | Cooldown crítico | 0 |
| `WEB_SEND_COOLDOWN_HIGH` | Cooldown alto | 15 |

### Batch Mode

| Variable | Descripción | Default |
|----------|-------------|---------|
| `WEB_USE_BATCH_MODE` | Habilitar batching | true |
| `WEB_BATCH_SIZE` | Eventos por batch | 20 |
| `WEB_BATCH_TIMEOUT` | Timeout flush (seg) | 30 |

---

## 11. Múltiples WebAgents

Puedes ejecutar múltiples WebAgents en paralelo:

```powershell
# Estructura recomendada
webagent/
webagent2/
webagent3/
```

### Reglas

1. **WEB_AGENT_ID único** - Cada agente diferente
2. **WEB_API_KEY compartida** - Misma clave en servidor
3. **WEB_LOG_FILE diferente** - Archivos de log distintos

### Ejemplo de Configuración Múltiple

```
webagent/.env:
  WEB_AGENT_ID=web-srv-01
  WEB_LOG_FILE=data/apache_access.log

webagent2/.env:
  WEB_AGENT_ID=web-srv-02
  WEB_LOG_FILE=data/nginx_access.log
```

---

## 12. Troubleshooting

| Error | Solución |
|-------|----------|
| `WEB_LOG_FILE no configurado` | Agregar en .env |
| `Archivo no encontrado` | Verificar ruta y permisos |
| `Server not reachable` | Verificar SERVER_URL |
| `SSL verification failed` | WEB_VERIFY_SSL=false (dev) |
| `401 Unauthorized` | Verificar WEB_API_KEY |
| No detecta ataques | Verificar formato de log |

### Formato de Log Esperado

```
127.0.0.1 - - [21/Apr/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

---

## 13. Módulos

| Módulo | Descripción |
|--------|-------------|
| `web_agent.py` | Agente principal |
| `config.py` | Configuración |
| `security.py` | Sanitización de datos |
| `persistence.py` | Persistencia de estado |
| `base.py` | Clase AgentBase |
| `patterns/` | Patrones de detección |
| `patterns/web.py` | Patrones Apache/Nginx |

---

## 14. Ejemplo de Eventos

### SQL Injection Detectado
```json
{
  "event_type": "sqli_attempt",
  "source_ip": "192.168.1.100",
  "risk": 35,
  "extra_data": {
    "path": "/admin/login",
    "user_agent": "sqlmap/1.0"
  }
}
```

### HTTP Flood Detectado
```json
{
  "event_type": "http_flood_start",
  "source_ip": "10.0.0.50",
  "risk": 25,
  "attempts_count": 150,
  "extra_data": {
    "paths": ["/", "/login", "/search"]
  }
}
```

---

## Version History

| Version | Fecha | Cambios |
|---------|-------|---------|
| 1.0 | 2026-04-16 | Versión inicial |
| 2.0 | 2026-04-18 | Múltiples patrones de inyección |
