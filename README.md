# SOC Platform

Plataforma SOC para detección de amenazas en tiempo real.

## Componentes

| Componente | Descripción | Estado | Puerto | Manual |
|------------|-------------|-------|--------|--------|
| **server/** | API Flask + SQLite | ✅ Stable | 5000 | [MANUAL.md](server/MANUAL.md) |
| **agent/** | Agente seguridad SSH | ✅ Stable | - | [MANUAL.md](agent/MANUAL.md) |
| **agent2/** | Agente seguridad SSH (copia) | ✅ Stable | - | [MANUAL.md](agent/MANUAL.md) |
| **webagent/** | Agente web (Apache/Nginx) | 🚧 En desarrollo | - | [webagent/web_agent.py](webagent/web_agent.py) |
| **dashboard/** | Dashboard web Flask | ✅ Stable | 8000 | [MANUAL.md](dashboard/MANUAL.md) |
| **pcap/** | Analizador PCAP/Zeek | 🚧 En desarrollo | - | [MANUAL.md](pcap/MANUAL.md) |

## Inicio

```bash
# Servidor (puerto 5000)
python run_server

# Agentes
python run_agent     # Agente 1
python run_agent2   # Agente 2 (multi-agente)

# Dashboard (puerto 8000)
python run_dashboard

# PCAP Analyzer
python run_pcap captura.pcap
python run_pcap /var/log/zeek/ --format zeek
```

## Mejoras Recientes

| Mejora | Componente | Descripción |
|--------|-----------|-------------|
| Tweets con microsegundos | server/agent | Timestamps con precision de microsegundos |
| Deduplicacion mejorada | server/pcap | Agrupa eventos por attack_type + src_ip |
| HTTPS por defecto | pcap | SERVER_URL ahora usa HTTPS |
| Retry con backoff | pcap | Reintento exponencial en envios |
| Extra_data JSON | pcap | Formato JSON string como agentes |
| Alertas async | server | Telegram con cola y worker thread |
| Graficos mejorados | dashboard | Severity cards + bar chart |
| Stats completos | dashboard | Stats sobre todos los registros |

## Documentación

- 📄 **[Seguridad](docs/Seguridad.md)** - Medidas de seguridad
- 📄 **[GUIA-CERTIFICADOS](docs/GUIA-CERTIFICADOS.md)** - Certificados SSL
- 📄 **[IMPLEMENTACION-PCAP](docs/IMPLEMENTACION-PCAP.md)** - Análisis PCAP
- 📄 **[ROADMAP](ROADMAP.md)** - Evolución del proyecto
