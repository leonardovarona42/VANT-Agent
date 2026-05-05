# VANT-Agent

Agente de recolección de eventos y seguridad para endpoints, parte del ecosistema **VANT-SIEM**.

> **Servidor SIEM**: [VANT-SIEM](https://github.com/anomalyco/VANT-SIEM)

## Descripción

VANT-Agent se instala en los endpoints (Windows/Linux) y se encarga de:

- **Recolección multi-fuente**: Snort, Suricata, Windows Event Log, PostgreSQL, file logs
- **Inventario de hardware/software**: CPU, memoria, disco, software instalado, red, USB
- **DLP (Aegis)**: Detección de fuga de información clasificada
- **Envío al servidor**: Comunicación con VANT-SIEM vía API REST

## Arquitectura

```
VANT-Agent (endpoint)
    │
    ├── agent.py           → Orchestrator principal
    ├── collectors/        → Recolectores de logs
    │   ├── snort.py
    │   ├── suricata.py
    │   ├── windows_eventlog.py
    │   ├── postgres_log.py
    │   └── file_log.py
    ├── services/
    │   ├── aegis_dlp.py   → Motor DLP
    │   └── audit_inventory.py → Inventario
    ├── config.yaml        → Configuración del agente
    └── windows/           → Agente empaquetado para Windows
```

## Flujo de datos

```
Endpoint                    VANT-SIEM Server
    │                            │
    ├── POST /api/agent/enroll/ ─┤
    ├── POST /api/agent/heartbeat/ ─┤
    ├── POST /api/agent/inventory/ ─┤
    ├── POST /api/agent/dlp/incidents/ ─┤
    ├── POST /os-service/api/v1/events/bulk/ ─┤
    └── POST /api/agent/commands/pull/ ─┤
```

## Instalación

### Windows

1. Descargar el instalador desde releases
2. Ejecutar `opensearch_agent_setup.exe`
3. Configurar la IP del servidor VANT-SIEM
4. El agente se registra automáticamente

### Linux (Debian/Ubuntu/Zentyal)

```bash
cd linux/
sudo ./build_linux.sh
sudo systemctl start vant-agent
```

## Configuración

El archivo `config.yaml` define:

- **server_url**: URL del servidor VANT-SIEM
- **collectors**: Fuentes de logs habilitadas
- **aegis_dlp**: Políticas de DLP
- **heartbeat**: Intervalo de heartbeat

Ver `config.example.yaml` para referencia completa.

## Desarrollo

```bash
python -m venv venv
source venv/bin/activate  # Linux
venv\Scripts\activate     # Windows
pip install -r requirements.txt

# Ejecutar agente manualmente
python agent.py

# Verificar configuración
python opensearchcheck.py
```

## Relación con VANT-SIEM

| Componente | Repo | Función |
|-----------|------|---------|
| **VANT-Agent** | Este repo | Agente de endpoint |
| **VANT-SIEM** | [github.com/anomalyco/VANT-SIEM](https://github.com/anomalyco/VANT-SIEM) | Servidor SIEM, dashboard, IA |

El agente **no funciona sin** VANT-SIEM. El servidor proporciona:
- API de ingesta de eventos
- Gestión de agentes (enroll, heartbeat, comandos)
- Políticas DLP centralizadas
- Dashboard de monitoreo

## Licencia

MIT - © 2025 VANT-SIEM Team
