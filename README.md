# VANT-Agent

Agente de recoleccion de eventos y seguridad para endpoints, parte del ecosistema **VANT-SIEM**.

> **Servidor SIEM**: [VANT-SIEM](https://github.com/leonardovarona42/VANT-SIEM)

## Descripcion

VANT-Agent se instala en los endpoints (Windows/Linux) y se encarga de:

- **Recoleccion multi-fuente**: Snort, Suricata, Windows Event Log, PostgreSQL, file logs
- **Inventario de hardware/software**: CPU, memoria, disco, software instalado, red, USB
- **DLP (Aegis)**: Deteccion de fuga de informacion clasificada
- **Envio al servidor**: Comunicacion con VANT-SIEM via API REST

## Arquitectura

```
VANT-Agent (endpoint)
    │
    ├── vant/
    │   ├── main.py             → Orchestrator principal
    │   ├── tray.py             → System tray GUI (Windows)
    │   ├── config.py           → Carga y validacion de config
    │   ├── api.py              → Cliente HTTP unificado
    │   ├── utils.py            → Helpers (host detection, logging)
    │   └── modules/
    │       ├── collectors/     → Recolectores de logs
    │       │   ├── snort.py
    │       │   ├── suricata.py
    │       │   ├── windows_eventlog.py
    │       │   ├── postgres_log.py
    │       │   └── file_log.py
    │       ├── inventory/      → Inventario HW/SW
    │       │   ├── collector.py
    │       │   ├── models.py
    │       │   └── service.py
    │       ├── dlp/
    │       │   └── aegis.py    → Motor DLP
    │       └── heartbeat/
    │           └── service.py  → Heartbeat + comandos
    │
    ├── config.yaml             → Configuracion del agente
    └── installer/              → Windows installer
        ├── vant_agent.iss      → Inno Setup script
        └── build_installer.ps1 → PowerShell builder
```

## Flujo de datos

```
Endpoint                    VANT-SIEM Server
    │                            │
    ├── POST /inventory/api/register/ ─┤
    ├── POST /inventory/api/heartbeat/ ─┤
    ├── POST /inventory/api/inventory/submit/ ─┤
    ├── POST /inventory/api/command-result/ ─┤
    ├── POST /logs/api/ingest/bulk/ ─┤
    └── POST /logs/api/sources/ ─┤
```

## Instalacion

### Windows

1. Descargar el instalador desde releases
2. Ejecutar `VANT-Agent-Setup.exe`
3. Configurar la IP del servidor VANT-SIEM en el wizard
4. El agente se registra automaticamente y arranca como servicio

### Ejecucion manual

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m vant.main --config config.yaml
```

## Configuracion

El archivo `config.yaml` define:

- **server.url**: URL del servidor VANT-SIEM (puerto 8000 para control/inventory)
- **server.logs_url**: URL del servicio de logs (puerto 9201)
- **agent**: hostname, intervalo, heartbeat
- **collectors**: Fuentes de logs habilitadas
- **inventory**: intervalo de recoleccion de HW/SW
- **dlp**: Politicas de DLP

Ver `config.example.yaml` para referencia completa.

## Desarrollo

```bash
pip install -r requirements.txt

# Ejecutar agente manualmente
python -m vant.main --config config.yaml

# Ejecutar con system tray (Windows)
python -m vant.tray --config config.yaml
```

## Relacion con VANT-SIEM

| Componente | Repo | Funcion |
|-----------|------|---------|
| **VANT-Agent** | Este repo | Agente de endpoint |
| **VANT-SIEM** | [github.com/leonardovarona42/VANT-SIEM](https://github.com/leonardovarona42/VANT-SIEM) | Servidor SIEM, dashboard, IA |

El agente **no funciona sin** VANT-SIEM. El servidor proporciona:
- API de ingesta de eventos
- Gestion de agentes (register, heartbeat, comandos)
- Politicas DLP centralizadas
- Dashboard de monitoreo

## Licencia

MIT - 2025 VANT-SIEM Team
