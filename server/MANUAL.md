# server.py - Manual de Uso

> **Nota:** Este manual también aplica para `agent2/` (copia para multi-agente).

---

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[Manual del Agente](../agent/MANUAL.md)** - Agente SOC
- 📄 **[Manual del Dashboard](../dashboard/MANUAL.md)** - Dashboard web
- 📄 **[Seguridad](../docs/Seguridad.md)** - Medidas de seguridad
- 📄 **[GUIA-CERTIFICADOS](../docs/GUIA-CERTIFICADOS.md)** - Generación de certificados

---

## Inicio Rapido

```bash
cd C:\Datos\Curso\Proyecto\soc-platform\server
python server.py
```

El servidor estara disponible en `https://0.0.0.0:5000` (o `http://localhost:5000` si SSL no esta configurado).

## Seguridad de las Comunicaciones

El servidor implementa multiples capas de proteccion:

### Capas de Proteccion

| Capa | Proteccion | Implementacion |
|------|---------|---------------|
| **TLS/SSL** | Cifrado | HTTPS en todas las comunicaciones |
| **Autenticacion** | HTTP Basic + API Key | Usuario/password + X-API-Key |
| **Rate Limiting** | Token Bucket | Por IP (60-100 req/min) |
| **Firmas HMAC** | Integridad | SHA-256 con secret compartido |
| **Nonce + Timestamp** | Anti-replay | TTL configurable (default 300s) |
| **Bloqueo de IP** | Threat Detector | IPs maliciosos bloqueados |
| **Validacion de Inputs** | Sanitizacion | Previene SQL/XSS injection |

### Flujo de Seguridad

```
Agente/Dashboard ──HTTPS──> Servidor
              │              │
              │   ┌──────┴──────┐
              │   │ 1. Rate Limit check
              │   │ 2. Blocked IP check  
              │   │ 3. Nonce/Timestamp validation
              │   │ 4. HMAC signature validation
              │   │ 5. Input sanitization
              │   └──────────────┘
              │              │
              └─────<────────┘
                 (respuesta firmado)
```

### Autenticacion de Agentes (Required)

```
X-API-Key: <AGENT_API_KEY>
```

### Request Signing (Opcional pero recomendado)

Para mayor seguridad, los agentes pueden firmar sus requests con HMAC-SHA256:

**Headers requeridos:**
```
Content-Type: application/json
X-API-Key: <AGENT_API_KEY>
X-Request-ID: <nonce-timestamp-random>
X-Request-Timestamp: <unix-timestamp>
```

**Headers opcionales (con AGENT_API_SECRET):**
```
X-Request-Signature: HMAC-SHA256(method&path&nonce&timestamp)
```

### Response Signing

El servidor firma todas las respuestas cuando AGENT_API_SECRET esta configurado:

**Headers en respuesta:**
```
X-Response-Nonce: <nonce>
X-Response-Timestamp: <unix-timestamp>
X-Response-Signature: <hmac-signature>
```

### Nonce Validation

- Nonces expirados despues de NONCE_TTL_SECONDS (default 300s)
- Previene replay attacks

## Endpoints de Agentes

### POST /log

Recibe un evento de seguridad.

**Headers:**
```
Content-Type: application/json
X-API-Key: <AGENT_API_KEY>
X-Request-ID: <nonce>
X-Request-Timestamp: <unix-timestamp>
X-Request-Signature: <hmac>  # opcional
```

**Body:**
```json
{
  "agent_id": "server-01",
  "src_ip": "192.168.1.100",
  "risk": 25,
  "attack_type": "brute_force_start",
  "target_host": "192.168.1.1",
  "source": "auth.log",
  "severity": "HIGH",
  "event_time": "2026-04-16T10:30:00",
  "raw_log": "Failed password for root from 192.168.1.100"
}
```

**Respuesta:**
```json
{"status": "ok"}
```

### POST /log/batch

Recibe multiples eventos en una sola peticion.

**Headers:** Mismos que /log

**Body:**
```json
{
  "agent_id": "server-01",
  "events": [
    {"event": {...}},
    {"event": {...}}
  ]
}
```

### GET /stats

Obtiene estadisticas generales.

```bash
curl -H "X-API-Key: <KEY>" https://localhost:5000/stats
```

**Respuesta:**
```json
{
  "by_ip": [{"ip": "192.168.1.100", "count": 50}],
  "by_type": [{"type": "brute_force", "count": 30}],
  "total_logs": 1000
}
```

### GET /logs

Obtiene logs con filtros.

```bash
curl -H "X-API-Key: <KEY>" "https://localhost:5000/logs?limit=50&offset=0"
```

**Parametros:**
- `limit`: Numero de registros (max 1000)
- `offset`: Offset para paginacion

### GET /health

Verifica el estado del servidor.

```bash
curl https://localhost:5000/health
```

**Respuesta:**
```json
{
  "status": "healthy",
  "active_requests": 2,
  "queue_size": 10,
  "circuit_breaker_state": "closed"
}
```

## Dashboard API (Endpoints de Solo Lectura)

El servidor incluye una API REST completa para acceso remoto al dashboard con autenticacion y proteccion.

### Autenticacion

La Dashboard API usa HTTP Basic Auth:

```bash
curl -u admin:password https://localhost:5000/dashboard/stats
```

### Endpoints Disponibles

| Endpoint | Metodo | Descripcion | Rate Limit |
|----------|--------|-------------|------------|
| `/health` | GET | Estado del servidor (sin auth) | - |
| `/.well-known/<path>` | GET | Rutas de Chrome/devtools | - |
| `/metrics` | GET | Metricass para monitoreo | 60/min |
| `/dashboard/stats` | GET | Estadisticas generales | 30/min |
| `/dashboard/logs` | GET | Lista de logs con filtros | 60/min |
| `/dashboard/logs/<id>` | GET | Detalle de un log | 60/min |
| `/dashboard/agents` | GET | Lista de agentes | 30/min |
| `/dashboard/agents/<id>` | GET | Detalle de un agente | 30/min |
| `/dashboard/charts/top-ips` | GET | Datos para grafico de IPs | 30/min |
| `/dashboard/charts/by-type` | GET | Datos por tipo de ataque | 30/min |
| `/dashboard/charts/by-source` | GET | Datos por fuente | 30/min |
| `/dashboard/charts/by-agent` | GET | Datos por agente | 30/min |
| `/dashboard/charts/risk-dist` | GET | Distribucion de riesgo | 30/min |
| `/dashboard/charts/daily` | GET | Tendencias diarias | 30/min |
| `/dashboard/threats` | GET | Amenazas correlacionadas | 30/min |
| `/dashboard/threats/summary` | GET | Resumen de amenazas | 30/min |
| `/dashboard/threats/coordinated` | GET | Ataques coordinados | 30/min |
| `/dashboard/threats/compromised` | GET | Compromisos detectados | 30/min |
| `/dashboard/threats/<ip>` | GET | Detalle de amenaza | 30/min |
| `/dashboard/health` | GET | Estado del sistema | 100/min |

### GET /dashboard/stats

```bash
curl -u admin:password https://localhost:5000/dashboard/stats
```

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "total_logs": 1234,
    "total_agents": 3,
    "high_risk_events": 56,
    "critical_events": 30,
    "breach_events": 14,
    "risk_distribution": {
      "LOW": 1109,
      "MEDIUM": 100,
      "HIGH": 20,
      "CRITICAL": 30,
      "BREACH": 14
    },
    "severity_distribution": {
      "LOW": 1109,
      "MEDIUM": 100,
      "HIGH": 20,
      "CRITICAL": 30,
      "BREACH": 14
    }
  }
}
```

### Niveles de Riesgo

| Nivel | Rango | Descripcion |
|-------|-------|-------------|
| LOW | 0-14 | Eventos de bajo impacto |
| MEDIUM | 15-29 | Eventos de riesgo moderado |
| HIGH | 30-49 | Eventos de alto riesgo |
| CRITICAL | 50-99 | Eventos criticos |
| BREACH | 100+ | Brecha de seguridad confirmada |

### GET /dashboard/logs

```bash
curl -u admin:password "https://localhost:5000/dashboard/logs?page=1&per_page=50"
```

**Parametros:**
- `page`: Numero de pagina (default: 1)
- `per_page`: Items por pagina (default: 50, max: 100)
- `agent_id`: Filtrar por agente
- `source`: Filtrar por fuente
- `min_risk`: Filtrar por riesgo minimo
- `src_ip`: Filtrar por IP
- `severity`: Filtrar por severidad

**Respuesta:**
```json
{
  "status": "success",
  "data": [...],
  "meta": {
    "page": 1,
    "per_page": 50,
    "total": 1234,
    "total_pages": 25,
    "filters": {}
  }
}
```

### GET /dashboard/charts/daily

```bash
curl -u admin:password "https://localhost:5000/dashboard/charts/daily?days=7"
```

**Respuesta:**
```json
{
  "status": "success",
  "data": [
    {"date": "2026-04-10", "count": 150},
    {"date": "2026-04-11", "count": 200}
  ]
}
```

## Correlacion de Amenazas Multi-Agente

El servidor incluye un modulo de correlacion que analiza eventos de multiples agentes para detectar:
- **Ataques coordinados**: IPs vistas por multiples agentes
- **Compromiso de cuentas**: Login exitoso despues de brute force
- **Patrones complejos**: Correlacion de eventos en el tiempo

### Tabla threat_intel

Se crea automaticamente con los siguientes campos:
- `ip`: IP del atacante
- `attack_types`: Tipos de ataque detectados (JSON array)
- `agent_ids`: Agentes que vieron esta IP (JSON array)
- `agent_count`: Numero de agentes
- `max_risk`: Riesgo maximo observado
- `avg_risk`: Riesgo promedio
- `is_compromised`: Si se confirmo compromiso (BREACH)
- `is_coordinated`: Si fue vista por multiples agentes

### GET /dashboard/threats

```bash
curl -u admin:password "https://localhost:5000/dashboard/threats?min_risk=30&limit=10"
```

**Respuesta:**
```json
{
  "status": "success",
  "data": [
    {
      "ip": "185.243.115.84",
      "max_risk": 80,
      "agent_count": 2,
      "is_compromised": false,
      "is_coordinated": true,
      "attack_types": ["brute_force_start", "ssh_login_success"],
      "agent_ids": ["agent-srv-01", "agent-srv-02"]
    }
  ],
  "meta": {"total": 10}
}
```

### GET /dashboard/threats/summary

```bash
curl -u admin:password "https://localhost:5000/dashboard/threats/summary"
```

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "total_threats": 45,
    "compromised_count": 3,
    "coordinated_count": 12,
    "multi_agent_count": 15,
    "avg_risk": 42.5,
    "top_threats": [...]
  }
}
```

### GET /dashboard/threats/compromised

Retorna solo indicadores de compromiso (BREACH):
```bash
curl -u admin:password "https://localhost:5000/dashboard/threats/compromised"
```

### LOGICA DE CORRELACION

| Escenario | Resultado |
|-----------|-----------|
| IP vista por 2+ agentes | `is_coordinated = true` |
| Login exitoso despues de brute force | `is_compromised = true` |
| Riesgo >= 100 | `is_compromised = true` |
| Ataque coordinada + alto riesgo | Alerta critica a Telegram |

## Configuracion de SSL

1. Generar certificados con `data/Cert/generate_certs.py`
2. Copiar `server.crt` y `server.key` a la carpeta `server/`
3. Configurar en `.env`:

```env
ENABLE_SSL=true
SSL_CERT_FILE=server.crt
SSL_KEY_FILE=server.key
```

## Configuracion de Dashboard API

### Variables de Entorno

```env
DASHBOARD_AUTH_ENABLED=true
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=changeme
DASHBOARD_PASSWORD_HASH=$2b$12$...
DASHBOARD_API_KEY=your-api-key
DASHBOARD_API_SECRET=<hmac-secret-key>
DASHBOARD_RATE_LIMIT=100
DASHBOARD_RATE_LIMIT_BURST=20
NONCE_TTL_SECONDS=300
```

### Generar Hash de Password

```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'tupassword', bcrypt.gensalt()).decode())"
```

### Generar API Secret

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Proteccion contra Amenazas

### Auto-Bloqueo de IPs

El servidor detecta y bloquea automaticamente:

- **Fuerza Bruta**: IPs con mas de 5 intentos de auth fallidos en 15 minutos
- **Abuso de Rate Limit**: IPs con mas de 10 violaciones de rate limit

### Variables de Configuracion

```env
THREAT_THRESHOLD_AUTH=5
THREAT_THRESHOLD_RATE=10
THREAT_WINDOW_MINUTES=15
BLOCKED_IPS_FILE=blocked_ips.txt
```

### Verificar IPs Bloqueadas

```bash
cat blocked_ips.txt
```

### Desbloquear IP Manualmente

```python
from threat_detector import threat_detector
threat_detector.unblock_ip("192.168.1.100")
```

## Limitacion de Rate

### Rate Limiting de Agentes

| Parametro | Default | Descripcion |
|-----------|---------|-------------|
| `RATE_LIMIT_RPM` | 60 | Requests por minuto por IP |
| `RATE_LIMIT_BURST` | 20 | Burst allowance |
| `MAX_CONCURRENT_REQUESTS` | 50 | Maximo requests simultaneos |

### Rate Limiting de Dashboard API

| Tipo | Limite |
|------|--------|
| Global | 100/min |
| Stats | 30/min |
| Logs | 60/min |
| Charts | 30/min |

## Deduplicacion y Late Events

### Problema

Cuando un agente se desconecta y luego se reconecta, puede enviar eventos historicos (late reporting). El servidor debe manejar esto correctamente:

- Evitar duplicar eventos ya procesados
- Aceptar eventos de late reporting que son validos
- Ignorar eventos muy antiguos
- Mantener la correlacion actualizada

### Deduplicacion Compuesta

El servidor usa deduplicacion basada en clave compuesta:

```
hash = SHA256(ip + risk + attack_type + agent_id + event_timestamp)
```

Esto es mas robusto que la deduplicacion simple porque considera el timestamp real del evento.

### Variables de Configuracion

| Variable | Default | Descripcion |
|----------|---------|-------------|
| `DEDUP_WINDOW_MINUTES` | 2 | Ventana de deduplicacion (recomendado: 1-5min para alto volumen) |
| `MAX_EVENT_AGE_HOURS` | 24 | Maximo tiempo para aceptar eventos historicos |
| `ENABLE_RECORRELATION` | true | Habilitar re-correlacion periodica |
| `RECORRELATION_INTERVAL_HOURS` | 24 | Frecuencia de re-correlacion |

### Comportamiento

| Escenario | Resultado |
|-----------|-----------|
| Evento dentro de ventana + misma clave | Duplicado - ignorado |
| Evento fuera de ventana | Nuevo - insertado |
| Evento con timestamp > 24h | Muy antiguo - ignorado |
| Late reporting valido | Se procesa correctamente |

### Re-correlacion

El servidor ejecuta una re-correlacion periodica para:

- Actualizar amenazas con nuevos eventos historicos
- Corregir deduplicacion incorrecta
- Detectar ataques coordinados no vistos en tiempo real
- Recalcular indicadores de compromiso

La re-correlacion se ejecuta en un hilo separado cada 24 horas (configurable).

### Forzar Re-correlacion Manual

```python
from server.threat_correlation import re_correlate_all_threats

result = re_correlate_all_threats()
print(f"Procesados: {result['total_logs_processed']}")
print(f"Threats actualizados: {result['threats_updated']}")
```

## Timestamps con Microsegundos

Para mejor deduplicacion, el servidor ahora usa timestamps con precision de microsegundos.

**Formatos:**
- `event_time`: Cuando ocorreu el evento (con microsegundos)
- `report_time`: Cuando llego al servidor (con microsegundos)
- Formato: `YYYY-MM-DD HH:MM:SS.ffffff`

**Archivos modificados:**
- `agent/agent.py`, `agent/base.py`, `agent/patterns/auth.py`
- `agent2/agent.py`, `agent2/base.py`, `agent2/patterns/auth.py`
- `server/server.py`, `server/db.py`, `server/audit.py`

## Ordenamiento por Event Time

El dashboard ahora ordena los eventos por `event_time` (cuandooccurrio) en lugar de `timestamp` (cuando llego al servidor).

Esto permite visualizar los eventos en orden cronologico correcto, incluso con late reporting.

## Diferencia: Eventos vs Amenazas

| Seccion | Tipo de datos | Descripcion |
|---------|---------------|-------------|
| **Resumen** | Eventos (logs) | Cada evento recibido por los agentes |
| **Amenazas** | IPs unicas correlacionadas | IPs con patrones de ataque detectados |

Ejemplo:
- 236 eventos totales
- 100 criticos (eventos con riesgo 50-99)
- 28 breach (eventos con riesgo 100+)
- 16 amenazas (IPs unicas en threat_intel)
- 9 comprometidas (IPs con is_compromised=1)

## Audit Logging

Todas las acciones se registran en `audit.log`:

```bash
tail -f audit.log
```

**Formato:**
```json
{"timestamp": "2026-04-16T10:30:00.123456", "action": "AUTH_ATTEMPT", "user": "admin", "ip": "192.168.1.50", "details": {"success": true}}
```

## Debug

Para activar el modo debug de Flask:

```env
FLASK_DEBUG=true
```

**Advertencia:** No usar en produccion. El modo debug permite recarga automatica y muestra mensajes detallados de error.

## Base de Datos

La base de datos SQLite se encuentra en `./database.db`.

```bash
# Ver contenido
sqlite3 database.db ".tables"
sqlite3 database.db "SELECT COUNT(*) FROM logs"
```

## Alertas Telegram

El servidor puede enviar alertas automaticas a Telegram cuando se detectan eventos de alto riesgo.

### Configuracion

En `.env`:

```env
TELEGRAM_TOKEN=tu-token-del-bot
TELEGRAM_CHAT_ID=tu-chat-id
ALERT_THRESHOLD_RISK=50
```

### Umbral de Riesgo

| Valor | Eventos que generan alerta |
|-------|---------------------------|
| 10 | Medium, High, Critical |
| 30 | High, Critical |
| 50 | Solo Critical (recomendado) |
| 70 | Ataques confirmados |
| 100 | Solo eventos maximos |

**Recomendacion:** Usar `ALERT_THRESHOLD_RISK=50` para reducir ruido y enfocarse en eventos criticos.

### Implementacion Async

Las alertas Telegram se envian de forma asincrona usando:
- **Cola (Queue)**: Almacena alertas pendientes
- **Worker Thread**: Procesa alertas en background

Esto evita bloquear el procesamiento de eventos.

### Circuit Breaker

Si Telegram falla 5 veces consecutivas, se activa el circuit breaker que pausa los envios por 60 segundos para evitar sobrecarga.

## Monitoreo

Ver metricas del servidor:

```bash
curl -H "X-API-Key: <KEY>" https://localhost:5000/metrics
```

## Variables de Configuracion

### Servidor

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Host de escucha | 0.0.0.0 |
| `SERVER_PORT` | Puerto del servidor | 5000 |
| `ENABLE_SSL` | Habilitar HTTPS | true |
| `SSL_CERT_FILE` | Certificado SSL | server.crt |
| `SSL_KEY_FILE` | Clave privada SSL | server.key |

> **Nota importante sobre rutas:**
> Las rutas son relativas desde la carpeta `server/`. Usar `server.crt` para certificados en la misma carpeta.
> Para rutas absolutas: `SSL_CERT_FILE=C:/Datos/Curso/Proyecto/soc-platform/server/server.crt`

### Autenticacion

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `AGENT_API_KEY` | Clave para agentes (requerida) | - |
| `AGENT_API_SECRET` | Secret para HMAC de agentes (opcional) | - |
| `DASHBOARD_API_SECRET` | Secret para HMAC del dashboard (opcional) | - |
| `NONCE_TTL_SECONDS` | TTL de nonces (anti-replay) | 300 |

### Rate Limiting

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `RATE_LIMIT_RPM` | Requests por minuto por IP | 60 |
| `RATE_LIMIT_BURST` | Burst allowance | 20 |
| `MAX_CONCURRENT_REQUESTS` | Maximo requests simultaneos | 50 |
| `MAX_REQUEST_SIZE_KB` | Tamano maximo de request (KB) | 64 |
| `DASHBOARD_RATE_LIMIT` | Rate limit dashboard API | 100 |
| `DASHBOARD_RATE_LIMIT_BURST` | Burst dashboard | 20 |

### Threat Detection

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `THREAT_THRESHOLD_AUTH` | Intentos fallidos antes de bloquear | 5 |
| `THREAT_THRESHOLD_RATE` | Violaciones rate limit antes de bloquear | 10 |
| `THREAT_WINDOW_MINUTES` | Ventana de tiempo (minutos) | 15 |

### Base de Datos

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `DB_PATH` | Ruta a la base de datos SQLite | server/database.db |

### Circuit Breaker

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | Fallos para abrir circuit | 5 |
| `CIRCUIT_BREAKER_RECOVERY_TIMEOUT` | Segundos antes de recover | 60 |

### Telegram

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `TELEGRAM_TOKEN` | Token del bot | - |
| `TELEGRAM_CHAT_ID` | Chat ID | - |
| `ALERT_THRESHOLD_RISK` | Umbral de riesgo para alertas | 10 |

### Certificate Pinning

**Que es?**
Proteccion adicional contra ataques MITM. Especificas el fingerprint del certificado esperado.

**Como obtener el fingerprint:**
```bash
openssl x509 -in server.crt -fingerprint -sha256
```

**Como configurarlo en clientes:**
```env
# En agent/.env o dashboard/.env
CERT_PINS=sha256=AB:CD:EF:12:34:56:78:...
```

**Cuando usarlo:**
- Desarrollo: No necesario
- Produccion: Opcional
- Mobile apps: **Recomendado**

---

## Requisitos

```bash
pip install flask requests bcrypt
```
