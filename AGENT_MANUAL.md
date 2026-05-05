# VANT-SIEM OpenSearch Agent Manual

## Alcance

Este manual describe el flujo actual del agente `v1.01` para Windows y Linux:

- instalacion
- configuracion
- enrolamiento
- herramientas operativas

## Arquitectura

El agente recolecta eventos de multiples fuentes y los envia al servicio OpenSearch.

Flujo general:

1. Lee eventos de las fuentes configuradas.
2. Normaliza el payload.
3. Envia lotes a `output.endpoint`.
4. Reporta heartbeat, inventario y DLP al servidor Django usando `control.server_url`.

## Fuentes soportadas

- Snort
- Suricata
- Windows Event Log
- PostgreSQL
- File logs
- Samba AD

## Estructura de configuracion

Archivo base: `config.yaml`

Bloques importantes:

```yaml
agent:
  id: "agent-001"
  host_name: "host-01"
  interval_seconds: 10

output:
  endpoint: "http://SERVER:9201/api/v1/events/bulk"
  source_endpoint: "http://SERVER:9201/api/v1/sources/upsert"
  timeout_seconds: 10
  auth:
    mode: "token"
    username: ""
    password: ""
    token: ""
  tls:
    enabled: false
    verify: false
    ca_cert: ""

control:
  server_url: "http://SERVER:8000"
  require_https: false
  token: ""
  poll_seconds: 30
  inventory_seconds: 86400
```

Puntos clave:

- `output.auth.token` es el token usado para heartbeat, inventario y comandos.
- `control.server_url` apunta al Django que expone `/api/agent/*`.
- `output.endpoint` apunta al microservicio OpenSearch.

## Enrolamiento real

El agente no se enrola solo con `auth.mode: none`. El flujo real es:

1. `GET /api/agent/bootstrap/`
2. header `X-Agent-Id`
3. obtener secreto compartido
4. firmar `agent_id:host_name:timestamp` con HMAC-SHA256
5. `POST /api/agent/enroll/`
6. guardar el token recibido en `output.auth.token`

Campos enviados al enrolar:

- `agent_id`
- `host_name`
- `timestamp`
- `signature`
- `install_owner_account`
- `enrollment_code` cuando el servidor lo exige

## Windows

### Instalacion actual

Usar el instalador grafico:

```powershell
.\opensearch_agents\windows\opensearch_agent_setup.exe
```

En el paso `Probar conexion`, el setup:

- consulta `bootstrap`
- firma la solicitud
- llama `enroll`
- guarda el token en el config generado

Ademas instala:

- tarea programada del agente
- tray de monitoreo
- `asset_audit`
- `aegis_dlp`

Modos de instalacion:

- elevado: `C:\Program Files\VANT\OpenSearchAgent`
- sin elevar: `%LOCALAPPDATA%\VANT\OpenSearchAgent`

El instalador ahora detiene la tarea y los procesos del agente/tray antes de
copiar binarios para evitar fallos de `Access denied` durante actualizaciones.

Instalacion manual:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\Install-OpenSearchAgent.ps1 -RunNow
```

Instalacion manual en modo usuario:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\Install-OpenSearchAgent.ps1 -UserMode -RunNow
```

Reenrolamiento en Windows:

No existe un `opena_enroll.exe` separado en Windows. El reenrolamiento se hace
desde el setup con `Probar conexion`, que vuelve a ejecutar bootstrap, enroll y
persistencia del token en el `config.yaml`.

### Active Directory

Canales recomendados:

- `Security`
- `System`
- `Application`
- `Directory Service`
- `DNS Server`
- `DFS Replication`
- `Active Directory Web Services`

## Linux

### Instalacion actual

El flujo Linux es offline por bundle.

Primero construir el bundle:

```bash
./opensearch_agents/linux/build_linux.sh
```

Luego instalar por distro:

```bash
cd opensearch_agents/linux/debian
sudo ./install_agent.sh
```

Tambien aplica para `ubuntu` y `zentyal`.

### Enrolamiento en Linux

Hay dos caminos:

1. Durante el wizard CLI del `install_agent.sh`
2. Manualmente con `opena_enroll`

Comandos:

```bash
sudo opena_enroll
sudo opena_enroll --enrollment-code CODIGO-DEL-TICKET
sudo opena_enroll --bootstrap-key MI_SECRETO
```

El comando actualiza `/etc/vant-siem/config.yaml`.

### Debian WSL como servidor de testing

Si Debian WSL sera el servidor donde corren Django, el microservicio OpenSearch
y ademas un agente Linux local, el orden recomendado es:

1. Instalar `python3`, `python3-venv`, `python3-pip`, `postgresql`,
   `build-essential` y `libpq-dev`.
2. Crear `vant_siem`, `vant_opensearch` y las credenciales:
   `vantsiem / vantsiem123` y `postgres / postgres`.
3. Copiar el proyecto a `/opt/vant-siem` en vez de ejecutarlo desde `/mnt/c/...`.
4. Crear un venv en `/opt/vant-siem/.venv`.
5. Instalar el stack minimo:
   `Django`, `django-sslserver`, `requests`, `pandas`, `scikit-learn`, `Flask`.
6. Ejecutar `python manage.py migrate --noinput`.
7. Crear superusuario.
8. Asignar `192.168.12.43` a Debian WSL con un servicio `systemd` oneshot.
9. Levantar `vant-opensearch.service`.
10. Levantar `vant-siem.service`.
11. Crear `/etc/vant-siem-agent/config.yaml`.
12. Ejecutar:

```bash
cd /opt/vant-siem
source .venv/bin/activate
python opensearch_agents/linux/common/agent_tools.py --config /etc/vant-siem-agent/config.yaml enroll
python opensearch_agents/linux/common/agent_tools.py --config /etc/vant-siem-agent/config.yaml check
python opensearch_agents/linux/common/agent_tools.py --config /etc/vant-siem-agent/config.yaml heartbeat
```

13. Levantar `vant-siem-agent.service`.

En este escenario los endpoints recomendados del agente son:

```yaml
output:
  endpoint: "http://192.168.12.43:9201/api/v1/events/bulk"
  source_endpoint: "http://192.168.12.43:9201/api/v1/sources/upsert"

control:
  server_url: "http://192.168.12.43:8000"
```

Los comandos completos quedaron documentados en:

- `opensearch_agents/linux/debian/README.md`
- `docs/INSTALLATION.md`

## Herramientas operativas

### Linux

```bash
sudo opena_enroll
sudo opena_checker
sudo opena_mover --host 192.168.1.50 --port 9201
sudo sendheartbeat --config /etc/vant-siem/config.yaml
```

### Python source mode

```bash
python opensearchcheck.py
python opensearchmover.py --host nuevo-servidor --port 9201
python sendheartbeat.py --config config.yaml
```

## Endurecimiento del backend

El servidor puede exigir:

- `VANT_AGENT_SHARED_SECRET`
- `VANT_AGENT_ENFORCE_ALLOWLIST=1`
- `VANT_AGENT_ALLOWED=agent-001,host-01`
- `VANT_AGENT_REQUIRE_ENROLLMENT_TICKET=1`

Si el ticket es obligatorio, el agente debe enviar `--enrollment-code`.

## Verificacion

Despues del enrolamiento verificar:

1. El token existe en `output.auth.token`.
2. `opena_checker` responde sin error.
3. `sendheartbeat` llega a `/api/agent/heartbeat/`.
4. El agente aparece en el modulo `inventory`.
5. Los eventos llegan a `os_events_raw`.

## Solucion de problemas

### Error al enrolar

- revisar `control.server_url`
- revisar conectividad a `:8000`
- revisar reloj del host
- revisar secreto compartido o ticket
- revisar si el servidor exige HTTPS

### Error de token invalido

- reenrolar con `opena_enroll`
- confirmar que el token fue guardado en `output.auth.token`

### No aparecen eventos

- revisar `output.endpoint`
- revisar `output.tls.*`
- revisar permisos de lectura sobre los logs
- revisar estado del servicio del agente
