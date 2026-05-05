# Linux Offline Packaging

Este documento resume el flujo vigente de empaquetado offline para los agentes Linux.

## Layout del paquete

Cada distro genera un payload `vant-siem-agent-install/` con:

- `install.sh`
- `uninstall.sh`
- `config/agent.yaml`
- `bin/`
- `desktop/`
- `systemd/`
- `docs/`
- `manifest.json`

Dentro de `bin/` ya viajan los binarios autocontenidos del agente:

- `vant-opensearch-agent`
- `vant-opensearch-agent-tray`
- `vant-agent-tools`
- `vant-agent-cli`

Cada distro en `linux/dist/<distro>/` tambien recibe:

- `install.sh`
- `uninstall.sh`

Y en `linux/dist/` quedan los paquetes:

- `vant-siem-agent-<distro>_1.0.0_all.deb`
- `vant-siem-agent-<distro>.tar.gz`

## Flujo de instalacion soportado

1. Construir el payload en la maquina de empaquetado con `opensearch_agents/linux/build_linux.sh`.
2. Copiar `linux/dist/<distro>/` o el `.deb` a la maquina cliente.
3. Instalar con una de estas dos opciones:

Bundle:

```bash
sudo ./install.sh
sudo ./install.sh --gdisable
```

Paquete `.deb`:

```bash
sudo dpkg -i vant-siem-agent-<distro>_1.0.0_all.deb
sudo VANT_AGENT_GDISABLE=1 dpkg -i vant-siem-agent-<distro>_1.0.0_all.deb
```

## Overrides soportados

- `VANT_LINUX_DISTRO` selecciona `debian`, `ubuntu` o `zentyal`.
- `VANT_AGENT_PACKAGE_DIR` apunta a un bundle ya extraido.
- `VANT_AGENT_WIZARD=0` desactiva el asistente interactivo.
- `VANT_AGENT_GDISABLE=1` fuerza instalacion headless en `.deb`.

## Que hace el instalador offline

La maquina destino no necesita internet. El instalador solo:

- localiza un bundle precompilado o usa el contenido del `.deb`,
- ejecuta `vant-agent-cli` si hay terminal interactiva y el wizard esta habilitado,
- guarda la configuracion en `/etc/vant-siem/config.yaml`,
- prueba conectividad con el servidor configurado,
- intenta enrolar automaticamente durante la prueba,
- copia archivos a `/opt/vant-siem-agent`,
- instala el servicio `systemd`,
- instala el tray GUI solo si no se activa `--gdisable` o `VANT_AGENT_GDISABLE=1`,
- instala `sendheartbeat`, `opena_mover`, `opena_checker`, `opena_enroll` y `vant-agent-cli` en `/usr/local/bin`.

## Verificacion offline

Tras instalar, deben quedar disponibles:

```bash
sudo systemctl status vant-siem-agent
sudo opena_checker
sudo sendheartbeat
```

Si el auto-enrolamiento no logra token, la instalacion sigue siendo valida y el
agente puede completarse despues con:

```bash
sudo opena_enroll
```
