# Agente 2 (Multi-Agente)

Este directorio contiene una copia del agente para ejecutar múltiples agentes en paralelo.

## Propósito

Permite ejecutar múltiples agentes simultáneamente para:
- Pruebas de arquitectura multi-agente
- Monitoreo de múltiples servidores
- Balanceo de carga

## Configuración

Editar `agent2/.env` con:
- `AGENT_ID=agent-srv-02` (ID único)
- `TARGET_HOST=<nuevo-servidor>`
- `LOG_FILE=<archivo-de-log>`

## Documentación

Ver 📄 **[MANUAL.md](../agent/MANUAL.md)** para detalles completos del agente.