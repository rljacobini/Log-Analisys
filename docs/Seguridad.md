# Analisis de Seguridad - SOC Platform

**Fecha:** 18 de Abril 2026
**Version:** 2.0

---

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[Manual del Agente](../agent/MANUAL.md)** - Agente SOC
- 📄 **[Manual del Servidor](../server/MANUAL.md)** - Servidor API
- 📄 **[Manual del Dashboard](../dashboard/MANUAL.md)** - Dashboard web
- 📄 **[GUIA-CERTIFICADOS](GUIA-CERTIFICADOS.md)** - Generación de certificados

---

## Resumen Ejecutivo

Este documento describe las medidas de seguridad implementadas en la plataforma SOC, incluyendo vulnerabilidades identificadas, mitigaciones y recomendaciones para cada componente.

### Nivel de Seguridad: **A**

La plataforma implementa **defense in depth** con multiples capas de proteccion:

| Capa | Proteccion | Componente |
|------|----------|-----------|
| **Autenticacion** | API Key + HTTP Basic | Servidor, Dashboard |
| **Integridad** | HMAC-SHA256 | Todas las comunicaciones |
| **Anti-Replay** | Nonce + Timestamp | Todas las comunicaciones |
| **Confidencialidad** | TLS/SSL (configurable) | Todas las comunicaciones |
| **Rate Limiting** | Token bucket | IP + API Key |
| **Input Validation** | Type checking + sanitization | Todos los inputs |
| **SQL Protection** | Parametrized + Escape LIKE | Base de datos |

### Medidas de Seguridad vs Vulnerabilidades

Esta tabla muestra cada medida de seguridad, que vulnerabilidad mitiga y como configurarla:

| # | Medida | Protege Contra | Como Funciona | Donde Configurar |
|---|--------|------------|-----------|-------------|
| 1 | **TLS/SSL** | MITM | Cifra toda la comunicacion | **Server:** `ENABLE_SSL=true` + certs; **Agent:** `USE_SSL=true`; **Dashboard:** `DASHBOARD_USE_SSL=true` + certs |
| 2 | **API Key** | Acceso no autorizado | Solo clientes con clave valida pueden enviar eventos | Agent: `X_API_KEY=mi-clave`; Server: `AGENT_API_KEY=mi-clave` |
| 3 | **HTTP Basic Auth** | Acceso no autorizado al dashboard | Browser pide usuario/password | Dashboard: `DASHBOARD_USERNAME=admin`, `DASHBOARD_PASSWORD=pass` |
| 4 | **HMAC-SHA256** | Request falsificado | Firma digital del request para verificar que no fue alterado | Agent: `X_API_KEY_SECRET=secret`; Server: `AGENT_API_SECRET=secret` (deben ser iguales) |
| 5 | **Nonce + Timestamp** | Replay attacks | Cada request tiene ID unico + timestamp, expira en N segundos | Server: `NONCE_TTL_SECONDS=300` (5 min por defecto) |
| 6 | **Rate Limiting** | DoS, flooding | Limita requests por minuto por IP | Server: `RATE_LIMIT_RPM=60`, `RATE_LIMIT_BURST=20` |
| 7 | **Threat Detector** | Fuerza bruta | Bloquea IPs con demasiados intentos fallidos | Server: `THREAT_THRESHOLD_AUTH=5`, `THREAT_WINDOW_MINUTES=15` |
| 8 | **Input Sanitization** | SQL/XSS Injection | Limpia caracteres peligrosos de inputs | `security.py` en agente; validacion en servidor |
| 9 | **Certificate Pinning** | MITM con cert valido | Solo acepta certificado especifico (no cualquier CA valida) | Agent/Dashboard: `CERT_PINS=sha256=AB12...` (obtener con openssl) |
| 10 | **Circuit Breaker** | Fallos en cascade | Si servicio externo falla, pausa intentos por 60s | Server: `CIRCUIT_BREAKER_FAILURE_THRESHOLD=5`, `CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60` |
| 11 | **SQL Parametrizado** | SQL Injection | Usa parametros `?` en lugar de concatenar strings | En `db.py`: `cursor.execute("SELECT * WHERE id=?", (id,))` |
| 12 | **Escape LIKE** | LIKE Injection | Escapa `%` y `_` en LIKE statements | En `db.py`: `escape_like(texto)` |
| 13 | **Cooldown** | Spam de alertas | Evita enviar mismas alertas repetidamente | Agent: `SEND_COOLDOWN_DEFAULT=15` seg, `SEND_COOLDOWN_CRITICAL=0` |
| 14 | **Batching** | Sobrecarga servidor | Agrupa N eventos en un solo request | Agent: `USE_BATCH_MODE=true`, `BATCH_SIZE=20` |

> **Nota importante - Rutas de certificados SSL:**
> Las rutas de certificados deben ser relativas desde donde se ejecuta el script:
> - **Server:** `SSL_CERT_FILE=server.crt` (relativo a server/)
> - **Dashboard:** `DASHBOARD_CERT_FILE=../server/server.crt` (relativo a dashboard/)
> - Usar rutas absolutas para evitar confusion: `DASHBOARD_CERT_FILE=C:/Datos/Curso/Proyecto/soc-platform/server/server.crt`

---

## 1. Arquitectura de Seguridad

### 1.1 Diagrama de Componentes

```
                    ┌──────────────────────────────────┐
                    │         DASHBOARD                │
                    │  (app.py)                      │
                    │  ├── Modo Local: BD directa    │
                    │  └── Modo API: via REST        │
                    └───────────────┬──────────────┘
                                    │ HTTPS + Auth
                    ┌───────────────┴──────────────┐
                    │      SERVER SOC             │
                    │  (server.py)                 │
                    │  ├── /log (agentes)         │
                    │  ├── /log/batch            │
                    │  ├── Dashboard API           │
                    │  └── Dashboard API: Firmas │
                    └───────────────┬──────────────┘
                                    │ HTTPS + Auth
        ┌─────────────────────────────┼─────────────────────────────┐
        │                           │                             │
        ▼                           ▼                             ▼
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│ AGENTE       │          │ WEB AGENT   │          │ AGENTES    │
│ (agent.py)  │          │(web_agent) │          │ (futuros)  │
│ Logs: auth  │          │ Apache/Nginx│          │           │
└──────────────┘          └──────────────┘          └──────────────┘
```

### 1.2 Flujo de Comunicaciones Seguras

```
AGENTE ──(X-API-Key)────────────────────> SERVIDOR
        ──(X-Request-ID, Timestamp)──────>
        ──(X-Request-Signature: HMAC)────>

        <─(X-Response-Nonce)───────────────
        <─(X-Response-Timestamp)──────────
        <─(X-Response-Signature)─────────

DASHBOARD ──(HTTP Basic Auth)──────────────> SERVIDOR
          ──(X-Request-ID, Timestamp)──────>
          ──(X-Request-Signature)──��────────>

          <─(X-Response-Nonce)───────────────
          <─(X-Response-Timestamp)──────────
          <─(X-Response-Signature)───────────
```

---

## 2. Servidor (server/server.py)

### 2.1 Medidas de Seguridad

| Medida | Estado | Descripcion |
|--------|--------|-------------|
| Autenticacion API Key | ✅ | X-API-Key en headers |
| Request Signing | ✅ | HMAC-SHA256 (AGENT_API_SECRET) |
| Nonce + Timestamp | ✅ | Previene replay attacks |
| Rate Limiting | ✅ | Token bucket por IP |
| Rate Limiting por API Key | ✅ | Token bucket por X-API-Key |
| Validacion de entrada | ✅ | Validacion de campos obligatorios |
| Tamano maximo de request | ✅ | MAX_REQUEST_SIZE_KB (64KB) |
| Maximo requests concurrentes | ✅ | Semaphore para backpressure |
| Circuit Breaker | ✅ | Protege contra fallos en cascade |
| SQL parametrizado | ✅ | Previene injection |
| SQL LIKE escape | ✅ | Previene LIKE injection |
| SSL/TLS | ✅ | HTTPS con certificados |
| Deduplicacion | ✅ | Evita registros duplicados (SHA256) |
| Escape de datos | ✅ | Sanitizacion de mensajes |
| Response signing | ✅ | X-Response-Signature header |

### 2.2 Endpoints Protegidos

| Endpoint | Rate Limit | Firma | Nonce |
|---------|-----------|-------|-------|
| `/log` | ✅ IP + API Key | ✅ | ✅ |
| `/log/batch` | ✅ IP + API Key | ✅ | ✅ |
| `/agents` | ✅ API Key | - | - |
| `/stats` | ✅ API Key | - | - |
| `/health` | - | - | - |
| `/dashboard/*` | ✅ IP | ✅ | ✅ |

### 2.3 Variables de Entorno

```bash
# Seguridad basica
AGENT_API_KEY=<secret-32-chars>

# Request signing (recomendado)
AGENT_API_SECRET=<hmac-secret>
NONCE_TTL_SECONDS=300

# Dashboard API
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=changeme
DASHBOARD_PASSWORD_HASH=$2b$12$...
DASHBOARD_API_SECRET=<hmac-secret>
```

---

## 3. Dashboard (dashboard/app.py)

El dashboard opera en dos modos:

### 3.1 Modo Local (Acceso Directo a BD)

| Medida | Estado | Descripcion |
|--------|--------|-------------|
| Autenticacion HTTP Basic | ✅ | Username/password |
| Session secret | ✅ | Para cookies Flask |
| Conexion solo lectura | ✅ | Solo SELECTs |
| HTTPS forzado | ⚠️ | Configurable |

### 3.2 Modo API (Acceso Remoto)

| Medida | Estado | Descripcion |
|--------|--------|-------------|
| HTTP Basic Auth | ✅ | Same as local |
| Request Signing | ✅ | HMAC-SHA256 |
| Nonce + Timestamp | ✅ | Previene replay |
| Rate Limiting | ✅ | Token bucket |
| Certificate Pinning | ✅ | Via CERT_PINS |
| SSL Verification | ✅ | Configurable |
| Response Validation | ✅ | Verifica firma del servidor |

### 3.3 Variables de Entorno

```bash
# Modo de operacion
USE_REMOTE_API=false  # true para modo API

# Conexion API
SOC_API_URL=https://soc-server:5000
SOC_VERIFY_SSL=false

# Seguridad API (modo remoto)
DASHBOARD_API_SECRET=<hmac-secret>
CERT_PINS=SHA256-cert-pin
API_TIMEOUT=30
NONCE_TTL_SECONDS=300

# Seguridad Flask
SECRET_KEY=changeme
```

---

## 4. Agente (agent/agent.py)

### 4.1 Medidas de Seguridad

| Medida | Estado | Descripcion |
|--------|--------|-------------|
| Conexion HTTPS | ✅ | SSL/TLS habilitado |
| Verificacion SSL | ✅ | Configurable (VERIFY_SSL) |
| API Key autentica | ✅ | Header X-API-Key |
| Request Signing | ✅ | HMAC-SHA256 (X_API_KEY_SECRET) |
| Nonce + Timestamp | ✅ | Previene replay attacks |
| Timeout de requests | ✅ | REQUEST_TIMEOUT configurable |
| Retry con backoff | ✅ | Exponential backoff |
| Deduplicacion local | ✅ | Hash de logs procesados |
| Persistencia segura | ✅ | Archivo JSON en disco |
| No exposure de credenciales | ✅ | Solo en .env |
| Log Injection Prevention | ✅ | sanitize_log_string() |
| Command Injection Prevention | ✅ | Bloquea shell chars |
| Path Traversal Prevention | ✅ | validate_log_file_path() |
| IP Spoofing Prevention | ✅ | sanitize_ip_address() |
| ReDoS Prevention | ✅ | Patrones regex non-greedy |
| Sanitizacion de eventos | ✅ | Todos los datos limpiados |

### 4.2 Modulo de Seguridad (agent/security.py)

```python
# Funciones implementadas
sanitize_log_string()       # Elimina \r\n, shell chars
sanitize_raw_log()          # Para lineas de log
sanitize_ip_address()        # Validacion IPv4/IPv6
sanitize_user()             # Limpia nombres de usuario
sanitize_extra_data()         # Sanitiza diccionarios
validate_log_file_path()    # Previene path traversal
safe_regex_match()          # Previene ReDoS
make_safe_regex()           # Compila regex seguros
```

### 4.3 Caracteres Bloqueados

| Caracteres | Riesgo | Bloqueado |
|------------|--------|-----------|
| \x00-\x08, \x0b-\x1f | Control | ✅ |
| \r, \n | Nueva linea | ✅ |
| ; & \| | Separadores shell | ✅ |
| ` $ ( ) { } < > \ | Shell | ✅ |
| $(...) \`...\` | Subshell | ✅ |
| ../ %2e%2e | Path traversal | ✅ |

### 4.4 Variables de Entorno

```bash
# Conexion al servidor
SERVER_URL=https://servidor:5000/log
X_API_KEY=<secret>

# Request signing (recomendado)
X_API_KEY_SECRET=<hmac-secret>

# SSL
VERIFY_SSL=true
```

---

## 5. Web Agent (agent/web_agent.py)

### 5.1 Medidas de Seguridad

El WebAgent hereda todas las protecciones de AgentBase mas:

| Medida | Estado | Descripcion |
|--------|--------|-------------|
| Hereda de AgentBase | ✅ | Todas las del agente |
| Sanitizacion de URLs | ✅ | Paths limpiados |
| Validacion de status codes | ✅ | Solo 4xx/5xx relevantes |
| Rate limiting local | ✅ | Detecta HTTP flood |
| Proteccion contra scanners | ✅ | Detecta nikto, sqlmap, nmap |
| Request Signing | ✅ | WEB_API_SECRET |

### 5.2 Deteccion de Ataques Web

| Tipo | Riesgo | Descripcion |
|------|--------|-------------|
| sqli_attempt | 35 | SQL Injection |
| xss_attempt | 30 | Cross-Site Scripting |
| path_traversal | 40 | Path traversal |
| command_injection | 45 | Command injection |
| scanner_detection | 25 | Security scanner |
| http_flood_start | 25 | HTTP flood |
| 404_enumeration | 10 | Enumeracion 404 |
| file_upload_attempt | 35 | Subida de archivos |

### 5.3 Variables de Entorno

```bash
# Identificacion
WEB_AGENT_ID=web-srv-01
WEB_TARGET_HOST=192.168.1.20
WEB_SOURCE=apache

# Log
WEB_LOG_FILE=/var/log/apache2/access.log

# Conexion
WEB_SERVER_URL=https://servidor:5000/log
WEB_API_KEY=<secret>

# Request signing
WEB_API_SECRET=<hmac-secret>

# Deteccion
WEB_FLOOD_THRESHOLD=100
WEB_SUSPICIOUS_404_THRESHOLD=10
```

---

## 6. Base de Datos (server/db.py)

### 6.1 Medidas de Seguridad

| Medida | Estado | Descripcion |
|--------|--------|-------------|
| Consultas parametrizadas | ✅ | Previene SQL injection |
| Escape wildcards LIKE | ✅ | Previene LIKE injection |
| Indices optimizados | ✅ | Mejora rendimiento |
| Transacciones | ✅ | Atomicidad en writes |
| Row factory | ✅ | Acceso seguro por nombre |

### 6.2 Recomendaciones para Produccion

```python
# Limitar permisos del archivo
import os
os.chmod("database.db", 0o600)

# Encriptar datos sensibles
from cryptography.fernet import Fernet

class SecureDB:
    def __init__(self, key):
        self.cipher = Fernet(key)
    
    def encrypt_ip(self, ip):
        return self.cipher.encrypt(ip.encode()).decode()
    
    def decrypt_ip(self, encrypted_ip):
        return self.cipher.decrypt(encrypted_ip.encode()).decode()
```

---

## 7. Vulnerabilidades Identificadas y Corregidas

### 7.1 Log Injection (ALTA)

**Mitigacion:** `sanitize_log_string()` en `security.py`
- Elimina caracteres de nueva linea
- Bloquea caracteres shell peligrosos

### 7.2 Command Injection (ALTA)

**Caracteres bloqueados:**
- `;` `&` `|` Separadores
- `` ` `` `$()` Command substitution
- `>` `<` Redirecciones

### 7.3 Path Traversal (ALTA)

**Mitigacion:** `validate_log_file_path()`
- Lista de directorios permitidos
- Verificacion de normalizacion

### 7.4 IP Spoofing (MEDIA)

**Mitigacion:** `sanitize_ip_address()`
- Validacion estricta IPv4/IPv6
- Rechazo de caracteres especiales

### 7.5 ReDoS (MEDIA)

**Mitigacion:** Patrones regex non-greedy
- `.*` → `.*?`
- Eliminacion de quantificadores anidados

---

## 8. Matriz de Amenazas y Mitigaciones

| Amenaza | Probabilidad | Impacto | Mitigacion |
|---------|--------------|----------|------------|
| SQL Injection | BAJA | ALTO | Consultas parametrizadas + escape LIKE |
| Brute Force API | MEDIA | ALTO | Rate limiting + IP blocking |
| Credential Theft | BAJA | CRITICO | bcrypt hash + HTTPS |
| Replay Attack | MEDIA | ALTO | Nonce + Timestamp |
| Request Tampering | BAJA | ALTO | HMAC signature |
| MITM | BAJA | ALTO | TLS + Certificate pinning |
| DoS | MEDIA | MEDIO | Rate limiting + circuit breaker |
| XSS (Dashboard) | BAJA | MEDIO | Jinja2 auto-escaping |
| Log Injection | MEDIA | ALTO | sanitize_log_string() |
| Command Injection | MEDIA | ALTO | Shell chars bloqueados |
| Path Traversal | BAJA | ALTO | validate_log_file_path() |
| IP Spoofing | BAJA | MEDIO | sanitize_ip_address() |
| ReDoS | BAJA | MEDIO | Patrones non-greedy |
| Event Replay (Late Reporting) | MEDIA | MEDIO | Deduplicacion por timestamp + MAX_EVENT_AGE_HOURS |
| Duplicate Events | BAJA | MEDIO | log_exists_compound() con ventana configurable |

---

## 9. Checklist de Seguridad para Produccion

- [ ] Cambiar todas las API keys por valores unicos y largos (32+ caracteres)
- [ ] Configurar `VERIFY_SSL=true` en agentes
- [ ] Configurar request signing (`*_API_SECRET`)
- [ ] Cambiar `SECRET_KEY` del dashboard
- [ ] Cambiar credenciales HTTP Basic
- [ ] Habilitar `FLASK_DEBUG=false`
- [ ] Configurar `ALERT_THRESHOLD_RISK=50`
- [ ] Instalar certificados SSL validos (Let's Encrypt)
- [ ] Configurar firewall para limitar acceso
- [ ] Encriptar datos sensibles en BD
- [ ] Revisar logs por informacion sensible
- [ ] Configurar `CERT_PINS` para production
- [ ] Implementar backups de base de datos
- [ ] Configurar `MAX_EVENT_AGE_HOURS=24` para produccion
- [ ] Habilitar `ENABLE_RECORRELATION=true` para mantener inteligencia actualizada
- [ ] Configurar ventanas de deduplicacion apropiadas segun volumen

---

## 10. Glosario de Variables de Seguridad

| Variable | Componente | Descripcion |
|----------|-----------|-------------|
| `AGENT_API_KEY` | server | Autenticacion de agentes |
| `AGENT_API_SECRET` | server | Firmar requests de agentes |
| `DASHBOARD_API_KEY` | server | API key del dashboard |
| `DASHBOARD_API_SECRET` | server | Firmar requests del dashboard |
| `DEDUP_WINDOW_MINUTES` | server | Ventana de deduplicacion (default 60 min) |
| `MAX_EVENT_AGE_HOURS` | server | Maximo edad de eventos (default 24h) |
| `ENABLE_RECORRELATION` | server | Habilitar re-correlacion periodica |
| `RECORRELATION_INTERVAL_HOURS` | server | Intervalo re-correlacion (default 24h) |
| `X_API_KEY` | agent | Autenticacion del agente |
| `X_API_KEY_SECRET` | agent | Firmar requests del agente |
| `WEB_API_KEY` | web_agent | Autenticacion del web agent |
| `WEB_API_SECRET` | web_agent | Firmar requests del web agent |
| `DASHBOARD_API_SECRET` | dashboard | Firmar requests al servidor |
| `CERT_PINS` | dashboard | Certificate pinning |
| `NONCE_TTL_SECONDS` | all | Tiempo de expiracion de nonces |
| `VERIFY_SSL` | agent/web_agent | Verificar certificados SSL |

---

## 12. Pruebas de Seguridad

### 12.1 Verificar Modulos de Seguridad

```bash
# Agente
cd agent
python -c "from security import *; print('Security module OK')"

# Verificar patronesseguros
python -c "from patterns import get_patterns_for_source; print('Patterns OK')"
```

### 12.2 Probar Protecciones

```python
# Log Injection
from security import sanitize_log_string
result = sanitize_log_string("line1\n[ALERT]")
assert "[ALERT]" not in result

# Command Injection
result = sanitize_log_string("; curl evil.com")
assert ";" not in result

# Path Traversal
from security import validate_log_file_path
result = validate_log_file_path("../../../etc/passwd", ["/var/log"])
assert result == False

# IP Spoofing
from security import sanitize_ip_address
result = sanitize_ip_address("1.2.3.4; rm -rf /")
assert result == None
```

### 12.3 Probar API Firmas

```bash
# Generar secret
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Probar request con firma
curl -X POST https://servidor:5000/log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tu-key" \
  -H "X-Request-ID: test-123" \
  -H "X-Request-Timestamp: $(date +%s)" \
  -H "X-Request-Signature: <hmac-signature>" \
  -d '{"agent_id":"test","src_ip":"1.2.3.4","risk":10}'
```

---

## 13. Monitoreo de Seguridad

### 13.1 Logs de Auditoria

El servidor maine un log de auditoria en `audit.log`:

```json
{"timestamp": "2026-04-18T10:30:00", "action": "AUTH_ATTEMPT", "user": "admin", "ip": "192.168.1.50", "details": {"success": true}}
```

### 13.2 Eventos a Monitorear

| Evento | Severidad | Accion |
|--------|----------|--------|
| Failed auth attempts | ALTA | Investigar origen |
| Rate limit exceeded | MEDIA | Verificar si legitimo |
| IP blocked | ALTA | Revisar si falso positivo |
| Invalid signature | ALTA | Posible ataque |
| Old timestamp | BAJA | Verificar sincronizacion |

### 13.3 Scripts de Monitoreo

```bash
# Ver intentos de auth fallidos
grep "AUTH_ATTEMPT.*success.*false" audit.log

# Ver IPs bloqueadas
cat blocked_ips.txt

# Ver eventos de rate limit
grep "RATE_LIMIT" audit.log
```

---

## 14. Respuesta a Incidentes

### 14.1 Plan de Respuesta

| Paso | Accion |
|------|-------|
| 1 | Detectar la brecha |
| 2 | Aislar sistemas afectados |
| 3 | Preservar evidencia |
| 4 | Evaluar alcance |
| 5 | Notificar si es necesario |
| 6 | Remediar vulnerabilidad |
| 7 | Restaurar servicios |

### 14.2 Contatos de Emergencia

| Recurso | Contacto |
|---------|----------|
| Equipo de Seguridad | security@empresa.com |
| Administrador SOC | soc-admin@empresa.com |
| Telefono de emergencia | +XX-XXX-XXXX |

### 14.3 Comandos de Emergencia

```bash
# Bloquear IP manualmente
echo "1.2.3.4" >> blocked_ips.txt

# Desbloquear IP
# Editar blocked_ips.txt y remover la IP

# Detener servidor
pkill -f server.py

# Revocar API keys
# Editar .env y generar nuevas keys
```

---

## 15. Roadmap de Seguridad

### 15.1 Mejoras a Corto Plazo (1-3 meses)

| Prioridad | Mejora | Descripcion |
|----------|-------|-------------|
| ALTA | mTLS | Autenticacion mutua entre agentes y servidor |
| ALTA | Encriptacion BD | Cifrar datos sensibles en SQLite |
| MEDIA | Hash passwords | Usar argon2 en lugar de bcrypt |
| MEDIA | Audit centralizado | Enviar logs a sistema externo |

### 15.2 Mejoras a Mediano Plazo (3-6 meses)

| Prioridad | Mejora | Descripcion |
|----------|-------|-------------|
| MEDIA | SSO | Integrar con OAuth2/OIDC |
| BAJA | WAF | Web Application Firewall |
| BAJA | IDS/IPS | Integrar con Suricata |

### 15.3 Mejoras a Largo Plazo (6-12 meses)

| Prioridad | Mejora | Descripcion |
|----------|-------|-------------|
| MEDIA | PostgreSQL | Migrar de SQLite a PostgreSQL |
| BAJA | SIEM | Integrar con Splunk/Elastic |
| BAJA | Zero Trust | Implementar modelo Zero Trust |

### 15.4 Investigacion Futura

- **Threat Intelligence**: Integrar feeds de amenazas
- **Machine Learning**: Deteccion anomalias
- **Automatizacion**: Respuesta automatizada
- **Cloud**: Despliegue en Kubernetes

---

## 16. Referencias

| Recurso | URL |
|---------|-----|
| Documentacion API | server/MANUAL.md |
| Documentacion Agente | agent/MANUAL.md |
| Documentacion Dashboard | dashboard/MANUAL.md |
| Guia de Certificados | docs/GUIA-CERTIFICADOS.md |

---

## 17. Version History

| Fecha | Version | Cambios |
|-------|---------|---------|
| 2026-04-16 | 1.0 | Creacion inicial. Protecciones contra log injection, command injection, path traversal, IP spoofing, ReDoS. |
| 2026-04-18 | 2.0 | Unificacion de documentos. Request signing, Nonce/Timestamp, HMAC para todas las comunicaciones. |
| 2026-04-18 | 2.1 | Agregadas secciones de pruebas, monitoreo, respuesta a incidentes y roadmap. |