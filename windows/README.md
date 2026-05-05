# Windows Agent Setup

Este directorio contiene el flujo de empaquetado e instalacion del agente para Windows.

## Artefacto final

- `opensearch_agent_setup.exe`

## Build

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\build_setup.ps1
```

Si `opensearch_agent_setup.exe` esta en uso, el build deja una copia nueva con timestamp.

## Contenido

- `agent_setup_ui.py`: instalador grafico PyQt6
- `Install-OpenSearchAgent.ps1`: instalacion del agente en el host
- `Uninstall-OpenSearchAgent.ps1`: desinstalacion
- `Uninstall-VANT-OpenSearch-Agent.exe`: desinstalador ejecutable
- `configs/`: plantillas de configuracion Windows
- `package/`: payload preparado para el setup
- `vant-opensearch-agent-tray.exe`: icono y controles de bandeja del sistema
- `sendheartbeat.exe`: heartbeat manual
- `opena_mover.exe`: cambio de servidor
- `opena_checker.exe`: validacion operativa
- aliases legacy: `sendhearbet.exe`, `opena_cheker.exe`

## Capacidades incluidas

- Perfil de auditoria para Active Directory en Windows Server.
- Microservicio `asset_audit` para inventario y timeline del endpoint.
- Microservicio `aegis_dlp` para deteccion de informacion clasificada y sensible.
- Enrolamiento y validacion de token desde el boton `Probar conexion`.
- El instalador crea un acceso directo en `Startup` para lanzar el tray al iniciar sesion.
- El instalador registra desinstalacion en Windows.
- El directorio de instalacion aplica ACL endurecida y guarda metadata del owner.
- Si existe una instalacion previa, primero la desinstala y luego instala la nueva.

## Flujo del setup

1. Genera `config.yaml` desde el wizard.
2. Ejecuta `Probar conexion` para bootstrap, enroll y token.
3. Copia el payload en el host.
4. Registra la tarea programada del agente.
5. Instala tray, desinstalador y utilidades auxiliares.

## Modos de instalacion

- Si el setup corre elevado, instala en `C:\Program Files\VANT\OpenSearchAgent`.
- Si el setup corre sin privilegios de administrador, hace fallback automatico a `C:\Users\<usuario>\AppData\Local\VANT\OpenSearchAgent`.
- Antes de actualizar binarios, el instalador detiene la tarea programada y los procesos del agente y del tray para evitar bloqueos del `.exe`.

## Comandos utiles

Instalacion silenciosa en modo usuario:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\Install-OpenSearchAgent.ps1 -UserMode -RunNow
```

Instalacion elevada en `Program Files`:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\Install-OpenSearchAgent.ps1 -RunNow
```

Desinstalacion:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\VANT\OpenSearchAgent\Uninstall-OpenSearchAgent.ps1"
```

o, si fue en modo usuario:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\VANT\OpenSearchAgent\Uninstall-OpenSearchAgent.ps1"
```

## Desinstalacion

Opciones disponibles:

- `Uninstall-OpenSearchAgent.ps1`
- `Uninstall-VANT-OpenSearch-Agent.cmd`
- Entrada en "Apps & Features"
