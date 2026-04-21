# app.py - Manual de Uso

---

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[Manual del Agente](../agent/MANUAL.md)** - Agente SOC
- 📄 **[Manual del Servidor](../server/MANUAL.md)** - Servidor API
- 📄 **[Seguridad](../docs/Seguridad.md)** - Medidas de seguridad
- 📄 **[GUIA-CERTIFICADOS](../docs/GUIA-CERTIFICADOS.md)** - Generación de certificados

---

## Arquitectura

### Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────────┐
│                     SOC Server (Flask)                        │
│                                                             │
│   Puerto 5000              │      Puerto 5000              │
│   ┌─────────────┐          │      ┌─────────────────┐      │
│   │ Agent API   │          │      │ Dashboard API   │      │
│   │             │          │      │                 │      │
│   │ POST /log   │          │      │ GET /dashboard/*│      │
│   │ POST /batch │          │      │ (solo lectura)  │      │
│   │ GET /health │          │      │                 │      │
│   └─────────────┘          │      └─────────────────┘      │
│                              │                                │
│                    ┌─────────┴─────────┐                   │
│                    │      Shared DB     │                   │
│                    │      (SQLite)      │                   │
│                    └─────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ HTTPS
         ┌────────────────────┼────────────────────┐
         │                    │                    │
┌───────┴───────┐    ┌───────┴───────┐    ┌───────┴───────┐
│   Agent 1     │    │   Agent 2     │    │   Dashboard   │
│  (Puerto 5000) │    │  (Puerto 5000) │    │  (Puerto 8000)│
└───────────────┘    └───────────────┘    └───────────────┘
```

### Flujo de Datos en Modo Remoto

```
┌──────────────┐         ┌────────────────────────┐
│  Dashboard   │────────▶│      SOC Server      │
│  (Frontend) │  HTTPS  │                     │
│  :8000      │         │  :5000               │
│             │         │  /dashboard/*        │
└──────────────┘         └─────────┬───────────┘
                                  │
                          ┌───────┴───────┐
                          │   Shared DB   │
                          │   (SQLite)    │
                          └───────────────┘
```

## Inicio Rapido

```bash
cd C:\Datos\Curso\Proyecto\soc-platform\dashboard
python app.py
```

Acceder a `http://localhost:8000`

## Seguridad en la Comunicacion

El dashboard implementa multiples capas de proteccion para comunicaciones seguras:

### Capas de Proteccion

| Capa | Proteccion | Implementacion |
|------|---------|---------------|
| **TLS/SSL** | Cifrado | HTTPS en todas las comunicaciones |
| **Autenticacion** | HTTP Basic | Usuario/password configurado |
| **Rate Limiting** | Token Bucket | Por IP (30-60 req/min) |
| **Firmas HMAC** | Integridad | SHA-256 con secret compartido |
| **Nonce + Timestamp** | Anti-replay | TTL de 5 minutos |
| **Bloqueo de IP** | Threat Detector | IPs maliciosos bloqueados |
| **Validacion de Inputs** | Sanitizacion | Previene SQL/XSS injection |

### Flujo de Seguridad

```
Dashboard ──HTTPS──> Servidor
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

### Variables de Seguridad

```env
# Modo API Remota
USE_REMOTE_API=true
SOC_API_URL=https://servidor:5000
SOC_VERIFY_SSL=false

# Seguridad avanzada
DASHBOARD_API_SECRET=<hmac-secret>
```

## Autenticacion

Se requiere HTTP Basic Auth:

```
Usuario: admin
Contrasena: (configurada en .env)
```

## Dos Modos de Operacion

### Modo Local (Default)

El dashboard accede directamente a la base de datos SQLite del servidor.

```env
USE_REMOTE_API=false
DB_PATH=../server/database.db
```

### Modo Remoto (API)

El dashboard accede al servidor SOC via API REST.

```env
USE_REMOTE_API=true
SOC_API_URL=https://soc-server:5000
SOC_VERIFY_SSL=false

# Seguridad avanzada
DASHBOARD_API_SECRET=<hmac-secret>
```

**Ventajas del modo remoto:**
- Dashboard puede estar en un servidor separado
- Soporta acceso desde ubicaciones remotas
- Aprovecha la autenticacion y proteccion del servidor

**Seguridad del API (recomendado para produccion):**

1. En el servidor, configurar:
```env
DASHBOARD_API_SECRET=<secret-generado>
```

2. En el dashboard, agregar:
```env
DASHBOARD_API_SECRET=<mismo-secret>
```

**Headers de seguridad:**
```
X-Request-ID: <nonce>
X-Request-Timestamp: <unix-timestamp>
X-Request-Signature: HMAC-SHA256(method&path&nonce&timestamp)
```

**Certificate pinning (opcional):**
```env
CERT_PINS=SHA256-cert-pin
```

## Paginas

### Dashboard Principal (`/`)

Muestra:
- Estadisticas generales
- Top 10 IPs atacante
- Tipos de ataque
- Distribucion por fuente
- Eventos por agente
- Tabla de eventos recientes

**Filtros disponibles:**
- `?agent=<agente_id>` - Filtrar por agente
- `?source=<fuente>` - Filtrar por fuente
- `?min_risk=<n>` - Filtrar por riesgo minimo
- `?ip=<ip>` - Filtrar por IP
- `?page=<n>` - Pagina (default: 1)

**Ejemplo:**
```
http://localhost:8000/?agent=server-01&min_risk=15
```

### Agentes (`/agents`)

Lista todos los agentes con:
- Hostname
- IP
- Estado
- Total de eventos
- Maximo riesgo
- Ultimo evento

### Amenazas (`/threats`)

Pagina de amenazas correlacionadas multi-agente:
- Muestra todas las IPs detectadas como amenazas
- Indica si es un ataque coordenadas (visto por 2+ agentes)
- Indica si hay compromiso confirmado (BREACH)
- Enlaces a detalle de cada amenaza

### Diferencia: Resumen vs Amenazas

| Seccion | Tipo | Descripcion |
|---------|------|-------------|
| **Resumen** | Eventos | Cada evento recibido del servidor |
| **Amenazas** | IPs unicas | IPs con patrones de ataque detectados |

Esta diferencia es intentional:
- **Eventos**: Cuenta cada vez que un agente reporta un ataque
- **Amenazas**: IPs unicas que aparecen en multiples agentes o con indicadores de compromiso

Ejemplo de valores:
- 236 eventos totales
- 100 criticos (eventos con riesgo 50-99)
- 28 breach (eventos con riesgo 100+)
- 16 amenazas (IPs unicas en threat_intel)

### Ordenamiento

Los eventos se ordenan por `event_time` (cuando ocurrio el evento), no por `timestamp` (cuando llego al servidor). Esto permite mantener consistencia cronologica con late reporting.

### Estadisticas Completas

Los stats (total, CRITICAL, HIGH, MEDIUM, LOW, INFO) se calculan sobre **todos los registros** de la base de datos, no solo sobre la pagina actual. Esto asegura que los numeros sean correctos independientemente de los filtros de paginacion.

### Detalle de Amenaza (`/threats/<ip>`)

Muestra el detalle de una amenaza especifica:
- Nivel de riesgo (maximo y promedio)
- Tipos de ataque detectados
- Agentes que vieron esta IP
- Recomendaciones de accion
- Lista de eventos en logs

### Rutas Especiales

| Ruta | Metodo | Descripcion |
|-----|--------|-------------|
| `/health` | GET | Verifica estado del dashboard |
| `/.well-known/<path>` | GET/POST/PUT/DELETE | Rutas de Chrome/devtools |

**Ejemplo de health:**
```bash
curl http://localhost:8000/health
```
**Respuesta:**
```json
{"status": "healthy"}
```

## Configuracion

Crear archivo `.env` basado en `.env.example`:

```env
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=change-me
DB_PATH=../server/database.db
SECRET_KEY=random-secret-key
PAGE_SIZE=50

USE_REMOTE_API=false
SOC_API_URL=https://localhost:5000
SOC_VERIFY_SSL=false
```

### Modo API Remota

Para conectar el dashboard a un servidor SOC remoto:

1. Configurar el servidor con Dashboard API habilitada
2. En el dashboard, configurar:

```env
USE_REMOTE_API=true
SOC_API_URL=https://soc-server.example.com:5000
SOC_VERIFY_SSL=false
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=your-password
```

**Importante:** Las credenciales deben coincidir con las configuradas en el servidor.

## Conexion a API Remota

### Verificar Conexion

```python
from api_client import SOCAPIClient, create_client

client = create_client()
if client.check_connection():
    print("Conexion exitosa!")
else:
    print("Error de conexion")
```

### Endpoints de la API

El cliente `SOCAPIClient` proporciona metodos para todos los endpoints:

```python
client = create_client()

stats = client.get_stats()
logs = client.get_logs(page=1, per_page=50)
agents = client.get_agents()
health = client.get_health()

chart_ips = client.get_chart_top_ips(limit=10)
chart_types = client.get_chart_by_type()
chart_risk = client.get_chart_risk_dist()
chart_daily = client.get_chart_daily(days=7)
```

### Manejo de Errores

El cliente maneja automaticamente los errores:

```python
result = client.get_stats()
if result.get('status') == 'error':
    print(f"Error: {result.get('error')}")
```

## Graficos

El dashboard incluye:

1. **Top 10 IPs Atacantes** - Barras
2. **Tipos de Ataque** - Pie chart
3. **Por Fuente de Log** - Pie chart
4. **Eventos por Agente** - Barras
5. **Distribucion de Riesgo** - Barras (Bajo/Medio/Alto/Critico/Breach)
6. **Severity Cards** - Tarjetas con totales de CRITICAL, HIGH, MEDIUM, LOW, INFO
7. **Attack Type Chart** - Bar chart horizontal con tipos de ataque

### Niveles de Riesgo

| Nivel | Rango | Descripcion |
|-------|-------|-------------|
| Bajo | 0-14 | Eventos de bajo impacto |
| Medio | 15-29 | Eventos de riesgo moderado |
| Alto | 30-49 | Eventos de alto riesgo |
| Critico | 50-99 | Eventos criticos |
| Breach | 100+ | Brecha de seguridad confirmada |

> **Nota:** El modo API remota obtiene estos niveles desde el servidor. Asegurate de que el servidor este actualizado para mostrar correctamente Breach.

## Paginacion

Controlar tamano de pagina en `.env`:

```env
PAGE_SIZE=50
```

Navegar entre paginas con `?page=N`.

## Modo Debug

Para activar el modo debug de Flask:

```env
FLASK_DEBUG=true
```

**Advertencia:** No usar en produccion. El modo debug permite recarga automatica y muestra mensajes detallados de error.

## API Client

### Crear Cliente

```python
from api_client import SOCAPIClient

client = SOCAPIClient(
    base_url="https://soc-server:5000",
    username="admin",
    password="your-password"
)
```

### Metodos Disponibles

| Metodo | Descripcion |
|--------|-------------|
| `get_stats()` | Estadisticas generales |
| `get_logs(page, per_page, **filters)` | Logs con filtros |
| `get_log_detail(log_id)` | Detalle de un log |
| `get_agents()` | Lista de agentes |
| `get_agent_detail(agent_id)` | Detalle de un agente |
| `get_chart_top_ips(limit)` | Grafico de IPs |
| `get_chart_by_type()` | Grafico por tipo |
| `get_chart_by_source()` | Grafico por fuente |
| `get_chart_by_agent()` | Grafico por agente |
| `get_threats(min_risk, compromised, coordinated, limit)` | Amenazas correlacionadas |
| `get_threats_summary()` | Resumen de amenazas |
| `get_threats_coordinated()` | Ataques coordinados |
| `get_threats_compromised()` | Compromisos detectados |
| `get_threat_detail(ip)` | Detalle de amenaza |
| `get_chart_risk_dist()` | Distribucion de riesgo |
| `get_chart_daily(days)` | Tendencias diarias |
| `get_health()` | Estado del sistema |
| `check_connection()` | Verificar conexion |

## Requisitos

```bash
pip install flask chartkick requests bcrypt
```

## Variables de Configuracion

### Servidor Web

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `DASHBOARD_HOST` | Host de escucha | 0.0.0.0 |
| `DASHBOARD_PORT` | Puerto del dashboard | 8000 |

### Autenticacion

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `DASHBOARD_USERNAME` | Usuario HTTP Basic | admin |
| `DASHBOARD_PASSWORD` | Contrasena HTTP Basic | changeme |
| `SECRET_KEY` | Clave secreta Flask (min 32 chars) | - |

### Modo de Operacion

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `USE_REMOTE_API` | Usar API en vez de BD directa | false |
| `SOC_API_URL` | URL del servidor SOC | https://localhost:5000 |
| `SOC_VERIFY_SSL` | Verificar certificado SSL | false |
| `DB_PATH` | Ruta a la base de datos SQLite | server/database.db |

### Seguridad API

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `DASHBOARD_API_SECRET` | Secret para HMAC (opcional) | - |
| `API_TIMEOUT` | Timeout para requests (segundos) | 30 |
| `API_MAX_RETRIES` | Maximo reintentos | 3 |
| `API_RETRY_BACKOFF` | Backoff exponencial | 1.0 |
| `CLIENT_RATE_LIMIT` | Rate limit cliente (req/min) | 60 |
| `NONCE_TTL_SECONDS` | TTL para nonces | 300 |

### SSL/HTTPS

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `DASHBOARD_USE_SSL` | Habilitar HTTPS (para navegador) | false |
| `DASHBOARD_CERT_FILE` | Certificado SSL | ../server/server.crt |
| `DASHBOARD_KEY_FILE` | Clave privada SSL | ../server/server.key |

> **Nota importante sobre rutas:**
> Las rutas son relativas desde la carpeta `dashboard/`. Usar `../server/server.crt` para certificados en `server/`.
> Para rutas absolutas: `DASHBOARD_CERT_FILE=C:/Datos/Curso/Proyecto/soc-platform/server/server.crt`

### Certificate Pinning

**Que es?**
Proteccion adicional contra ataques Man-in-the-Middle (MITM). Especificas que solo aceptas UN certificado concreto, no cualquier certificado valido por una CA.

**Como obtener el fingerprint:**
```bash
openssl x509 -in server.crt -fingerprint -sha256
```

**Como configurarlo:**
```env
CERT_PINS=sha256=AB:CD:EF:12:34:56:78:...
```

**Cuando usarlo:**
| Situacion | Recomendacion |
|-----------|---------------|
| Desarrollo | No necesario |
| Produccion general | Opcional |
| Mobile apps | **Recomendado** |
| Datos muy sensibles | **Recomendado** |

> Nota: Si caduca el certificado del servidor, deberas actualizar el pin.

### Varios

| Variable | Descripcion | Default |
|----------|-------------|---------|
| `PAGE_SIZE` | Registros por pagina | 50 |
| `FLASK_DEBUG` | Modo debug de Flask | false |

---

## Estructura de Archivos

```
dashboard/
├── app.py              # Aplicacion principal
├── config.py           # Configuracion
├── api_client.py       # Cliente para API remota
├── templates/
│   ├── dashboard.html  # Plantilla principal
│   └── agents.html     # Plantilla de agentes
├── static/             # Archivos estaticos
└── .env                # Configuracion local
```

## Troubleshooting

### Error: Database not found

Verificar que `DB_PATH` en `.env` apunte a la ubicacion correcta de `database.db`.

### Error: Unauthorized

Verificar credenciales en `.env`:
```
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=your-password
```

### Error: Connection refused (modo API)

Verificar que el servidor SOC este corriendo y `SOC_API_URL` sea correcta.

### Error: SSL Certificate (modo API)

Si usas certificados auto-firmados:
```env
SOC_VERIFY_SSL=false
```

### Pagina en blanco

Verificar que la base de datos existe y tiene tablas:
```bash
sqlite3 ../server/database.db ".tables"
```

### Error 429: Rate limit exceeded

Se excedio el limite de requests. Esperar o contactar al administrador del servidor.

### Error 403: IP blocked

Tu IP fue bloqueada por demasiados intentos fallidos. Contactar al administrador.
