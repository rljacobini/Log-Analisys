# Guia de Certificados SSL para SOC Platform

**Fecha:** 16 de Abril 2026

---

### Documentación Relacionada

- 📄 **[README](../README.md)** - Información general del proyecto
- 📄 **[Manual del Agente](../agent/MANUAL.md)** - Agente SOC
- 📄 **[Manual del Servidor](../server/MANUAL.md)** - Servidor API
- 📄 **[Manual del Dashboard](../dashboard/MANUAL.md)** - Dashboard web
- 📄 **[Seguridad](Seguridad.md)** - Medidas de seguridad

---

## Indice

1. [Introduccion](#introduccion)
2. [Generar Certificados](#generar-certificados)
3. [Configuracion del Servidor](#configuracion-del-servidor)
4. [Configuracion del Agente](#configuracion-del-agente)
5. [Verificacion](#verificacion)
6. [Solucion de Problemas](#solucion-de-problemas)

---

## Introduccion

### Que es un certificado SSL?

Un certificado SSL/TLS permite la comunicacion cifrada entre el agente y el servidor. El servidor presenta el certificado para probar su identidad, y el agente verifica que es valido.

### Arquitectura de comunicacion

```
+---------+         HTTPS (cifrado)         +---------+
|  Agente | <------------------------------> | Servidor |
+---------+                                +---------+
     |                                           |
     |  1. Request con X-API-Key                 |
     |  2. Response con datos                    |
     |                                           |
     v                                           v
  Puerto 5000                                 Puerto 5000
```

### Archivos necesarios

| Archivo | Ubicacion | Descripcion |
|---------|-----------|-------------|
| `server.crt` | `server/` | Certificado publico del servidor |
| `server.key` | `server/` | Clave privada del servidor |

**Nota:** El agente NO necesita el certificado localmente (excepto si `VERIFY_SSL=true`).

---

## Generar Certificados

### Ubicacion del script

```
soc-platform/
├── data/
│   └── Cert/
│       └── generate_certs.py    <-- Script de generacion
└── server/
    ├── server.crt              <-- Se genera aqui
    └── server.key              <-- Se genera aqui
```

### Ejecutar el generador

```bash
cd data/Cert
python generate_certs.py
```

### Salida esperada

```
============================================================
GENERADOR DE CERTIFICADOS SSL
============================================================

[*] Generando clave privada RSA (2048 bits)...
[*] Guardando clave privada en ...server\server.key...
[*] Generando certificado X.509...
[*] Guardando certificado en ...server\server.crt...

============================================================
CERTIFICADOS GENERADOS EXITOSAMENTE
============================================================
  Certificado: ...server\server.crt
  Clave:       ...server\server.key
  CN:          SOC-Dev-Localhost
  SANs:        localhost, 127.0.0.1, ::1, ...
  Clave:       2048 bits RSA
  Validez:     365 dias
  Hash:        SHA256
============================================================
```

### Parametros opcionales

Puedes personalizar el certificado:

```python
from generate_certs import generate_ssl_certs

generate_ssl_certs(
    cert_file="server/server.crt",
    key_file="server/server.key",
    common_name="Mi-Servidor",
    sans=["localhost", "192.168.1.100", "mi-servidor.local"],
    key_size=2048,        # 2048 o 4096
    validity_days=365      # Dias de validez
)
```

### Verificar certificados existentes

```bash
cd data/Cert
python -c "
import generate_certs
result = generate_certs.verify_certificate('../../server/server.crt', '../../server/server.key')
generate_certs.print_verification(result)
"
```

---

## Configuracion del Servidor

### Variables de entorno

Edita `server/.env`:

```bash
# Habilitar SSL (true/false)
ENABLE_SSL=true

# Rutas de certificados (relativas al directorio server/)
SSL_CERT_FILE=server.crt
SSL_KEY_FILE=server.key

# Puerto del servidor
SERVER_PORT=5000
```

### Verificar configuracion

```bash
cd server
python config.py
```

Salida esperada:

```
Configuracion del Servidor SOC
==================================================
  server_url: https://0.0.0.0:5000
  db_path: ./database.db
  rate_limit_rpm: 180
  ssl_enabled: True
  ssl_cert: server.crt
  ssl_key: server.key
==================================================
```

### Iniciar servidor con SSL

```bash
cd server
python server.py
```

El servidor iniciara con HTTPS:

```
==================================================
SERVIDOR SOC - Iniciado
==================================================
  server_url: https://0.0.0.0:5000
  ssl_enabled: True
  rate_limit_rpm: 180
==================================================
```

### Deshabilitar SSL (no recomendado)

```bash
# En server/.env
ENABLE_SSL=false
```

El servidor usara HTTP plano (sin cifrar).

---

## Configuracion del Agente

### Opcion 1: No verificar SSL (Desarrollo)

La forma mas simple. El agente no verifica el certificado.

```bash
# En agent/.env
USE_SSL=true
VERIFY_SSL=false
```

**Pros:** Simple, sin instalacion
**Cons:** Vulnerable a ataques man-in-the-middle

### Opcion 2: Verificar con archivo de certificado

```bash
# En agent/.env
USE_SSL=true
VERIFY_SSL=true

# Ruta al certificado del servidor
# (puede ser absoluta o relativa)
SSL_CERT_FILE=../server/server.crt
```

### Opcion 3: Instalar en sistema operativo

**Windows (PowerShell como Administrador):**
```powershell
Import-Certificate -FilePath "C:\ruta\server.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

**Windows (CMD como Administrador):**
```cmd
certutil -addstore Root "C:\ruta\server.crt"
```

**Linux (Debian/Ubuntu):**
```bash
sudo cp server.crt /usr/local/share/ca-certificates/soc-server.crt
sudo update-ca-certificates
```

**Linux (RHEL/CentOS):**
```bash
sudo cp server.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust enable
sudo update-ca-trust extract
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain server.crt
```

Despues de instalar en el sistema:

```bash
# En agent/.env
USE_SSL=true
VERIFY_SSL=true
# No necesitas SSL_CERT_FILE si usas certificados del sistema
```

### Configuracion completa del agente

```bash
# En agent/.env

# Servidor
SERVER_URL=https://localhost:5000/log
X_API_KEY=tu-clave-secreta

# SSL/TLS
USE_SSL=true
VERIFY_SSL=true
SSL_CERT_FILE=../server/server.crt

# Monitoreo
AGENT_INTERVAL=10
SOURCE=auth.log
LOG_FILE=../data/auth.log

# Deteccion
BRUTE_FORCE_THRESHOLD=5
BRUTE_FORCE_WINDOW=60

# Batching (reducir carga en servidor)
USE_BATCH_MODE=true
AGENT_BATCH_SIZE=20
AGENT_BATCH_TIMEOUT=30
```

### Verificar configuracion

```bash
cd agent
python config.py
```

Salida esperada:

```
Configuracion del Agente SOC
==================================================
  agent_id: agent-001
  server_url: https://localhost:5000/log
  ssl_enabled: True
  ssl_verify: True
  ssl_cert: ../server/server.crt
  batch_mode: True
  batch_size: 20
==================================================
```

---

## Verificacion

### 1. Verificar certificados

```bash
cd data/Cert
python generate_certs.py --verify
```

### 2. Probar conexion del agente

```bash
cd agent
python -c "
import requests
import os
from dotenv import load_dotenv

load_dotenv('.env')

cert_file = os.getenv('SSL_CERT_FILE', '../server/server.crt')
verify = os.getenv('VERIFY_SSL', 'false').lower() == 'true'

try:
    if verify:
        response = requests.get(
            'https://localhost:5000/health',
            verify=cert_file if os.path.exists(cert_file) else True,
            timeout=5
        )
    else:
        import urllib3
        urllib3.disable_warnings()
        response = requests.get(
            'https://localhost:5000/health',
            verify=False,
            timeout=5
        )
    print(f'OK: Servidor respondio con status {response.status_code}')
    print(f'Response: {response.json()}')
except Exception as e:
    print(f'Error: {e}')
"
```

### 3. Verificar logs del servidor

```bash
# En la terminal del servidor
python server.py

# Deberias ver:
# SERVIDOR SOC - Iniciado
# HTTPS habilitado con certificados: server.crt
```

### 4. Probar envio de eventos

```bash
cd agent
python agent.py
```

---

## Solucion de Problemas

### Error: "certificate verify failed"

**Causa:** El agente no puede verificar el certificado.

**Solucion 1:** Deshabilitar verificacion (desarrollo)
```bash
VERIFY_SSL=false
```

**Solucion 2:** Especificar archivo de certificado
```bash
VERIFY_SSL=true
SSL_CERT_FILE=../server/server.crt
```

**Solucion 3:** Instalar certificado en el sistema operativo.

---

### Error: "Connection refused"

**Causa:** El servidor no esta corriendo o esta en otro puerto.

**Solucion:**
1. Verificar que el servidor este corriendo
2. Verificar el puerto en `SERVER_URL` del agente

```bash
# Verificar servidor
cd server
python server.py

# Verificar que el agente apunte al puerto correcto
# En agent/.env
SERVER_URL=https://localhost:5000/log
```

---

### Error: "SSL handshake failed"

**Causa:** El certificado esta corrupto o expiro.

**Solucion:** Regenerar certificados

```bash
cd data/Cert
python generate_certs.py
```

---

### Error: "ModuleNotFoundError: No module 'requests'"

**Causa:** Faltan dependencias.

**Solucion:**

```bash
pip install requests cryptography python-dotenv flask
```

---

### Error: "Permission denied" en clave privada

**Causa:** Permisos incorrectos en Windows.

**Solucion:**
```powershell
icacls server.key /inheritance:r /grant:r "%USERNAME%:(R)"
```

---

### Error: "EOF when reading a line"

**Causa:** El script no puede pedir input interactivo.

**Solucion:** Regenerar sin preguntar

```bash
cd data/Cert
echo "s" | python generate_certs.py
```

---

## Resumen Rapido

### Para desarrollo rapido

```bash
# 1. Generar certificados
cd data/Cert
python generate_certs.py

# 2. Configurar agente (desarrollo)
# agent/.env
USE_SSL=true
VERIFY_SSL=false

# 3. Iniciar servidor
cd server
python server.py

# 4. Iniciar agente
cd agent
python agent.py
```

### Para produccion

```bash
# 1. Generar certificados
cd data/Cert
python generate_certs.py

# 2. Instalar certificado en sistema
certutil -addstore Root server/server.crt

# 3. Configurar agente
# agent/.env
USE_SSL=true
VERIFY_SSL=true

# 4. Iniciar servidor
cd server
python server.py

# 5. Iniciar agente
cd agent
python agent.py
```

---

## Seguridad

### ADVERTENCIA

| Entorno | VERIFY_SSL | Seguridad |
|---------|------------|-----------|
| Desarrollo | `false` | Baja |
| Pruebas | `true` | Media |
| Produccion | `true` + instalar en SO | Alta |

**Nunca uses `VERIFY_SSL=false` en produccion.**

### Mejores practicas

1. **Usa certificados de una CA** en produccion (Let's Encrypt, etc.)
2. **Rota los certificados** antes de que expiren
3. **Protege la clave privada** con permisos restrictivos
4. **No compartas** `server.key` con nadie
5. **Usa passwords** para claves privadas en produccion

---

## Referencias

- [Documentacion de Flask SSL](https://flask.palletsprojects.com/en/2.0.x/deploying/wsgi-standalone/)
- [OpenSSL](https://www.openssl.org/)
- [Let's Encrypt](https://letsencrypt.org/)
