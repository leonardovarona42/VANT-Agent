# Linux Packs

La estructura Linux queda separada asi:

1. `common/` para assets y logica compartida.
2. `debian/` para defaults y guia de Debian.
3. `ubuntu/` para defaults y guia de Ubuntu.
4. `zentyal/` para defaults y guia de Zentyal/Samba AD.

El instalador compartido vive en `common/install_agent.sh` y cada distro solo
define su wrapper, su `config.yaml` y su guia operativa.

## Artefactos generados

`opensearch_agents/linux/build_linux.sh` genera por distro:

1. `linux/dist/<distro>/install.sh`
2. `linux/dist/<distro>/uninstall.sh`
3. `linux/dist/<distro>/vant-siem-agent-install/`
4. `linux/dist/vant-siem-agent-<distro>_1.0.0_all.deb`
5. `linux/dist/vant-siem-agent-<distro>.tar.gz`

El bundle y el `.deb` son offline. La maquina cliente no necesita `apt`, `pip`
ni acceso a internet para completar la instalacion del agente.

## Como instalar en cliente

Tienes dos formas soportadas.

### Opcion 1: bundle extraido

Con entorno grafico:

```bash
cd linux/dist/<distro>
sudo ./install.sh
```

Sin entorno grafico o forzando modo terminal:

```bash
cd linux/dist/<distro>
sudo ./install.sh --gdisable
```

### Opcion 2: paquete `.deb`

Instalacion normal:

```bash
sudo dpkg -i linux/dist/vant-siem-agent-<distro>_1.0.0_all.deb
```

Instalacion headless:

```bash
sudo VANT_AGENT_GDISABLE=1 dpkg -i linux/dist/vant-siem-agent-<distro>_1.0.0_all.deb
```

`dpkg` no acepta una bandera propia del paquete, por eso el modo headless en el
`.deb` se activa con `VANT_AGENT_GDISABLE=1`.

## Comportamiento del asistente

Durante la instalacion, si hay terminal interactiva disponible, se ejecuta el
asistente CLI del agente. Ese flujo:

1. Pide host y puerto del servidor de control y del endpoint OpenSearch.
2. Prueba conectividad con el servidor destino.
3. Intenta enrolar automaticamente el agente durante la prueba.
4. Guarda la configuracion en `/etc/vant-siem/config.yaml`.

Si el enrolamiento automatico no consigue token, la instalacion igual termina y
puedes reenrolar despues con `sudo opena_enroll`.

Para instalaciones desatendidas:

```bash
sudo VANT_AGENT_WIZARD=0 ./install.sh --gdisable
sudo VANT_AGENT_WIZARD=0 VANT_AGENT_GDISABLE=1 dpkg -i linux/dist/vant-siem-agent-<distro>_1.0.0_all.deb
```

## GUI vs headless

Modo normal:

1. Instala el servicio del agente.
2. Deja habilitado el tray GUI.
3. Crea `/etc/xdg/autostart/vant-siem-agent-tray.desktop`.

Modo `--gdisable` o `VANT_AGENT_GDISABLE=1`:

1. Instala el mismo servicio del agente.
2. Deshabilita el tray GUI.
3. Deja toda la configuracion y operacion desde terminal.

## Utilidades disponibles tras instalar

El paquete deja disponibles en `/usr/local/bin`:

1. `sendheartbeat` para forzar heartbeat manual.
2. `opena_mover --host <ip> --port <puerto>` para migrar el agente.
3. `opena_checker` para validar enrolamiento y conectividad.
4. `opena_enroll` para reenrolar o enrolar manualmente.
5. `vant-agent-cli` para reabrir el asistente desde terminal.

Ejemplos:

```bash
sudo opena_checker
sudo sendheartbeat
sudo opena_mover --host 192.168.12.43 --port 9201
sudo opena_enroll --enrollment-code CODIGO-DEL-TICKET
```

## Layout instalado

La instalacion deja principalmente:

1. `/opt/vant-siem-agent/` con binarios y runtime del agente.
2. `/etc/vant-siem/config.yaml` con la configuracion operativa.
3. `/usr/local/bin/` con los comandos auxiliares.
4. `/etc/systemd/system/vant-siem-agent.service` para el servicio.

Durante la instalacion, `/opt/vant-siem-agent` se asigna al usuario que ejecuto
el `sudo` cuando esa identidad esta disponible. La configuracion sensible queda
en `/etc/vant-siem/`.

## Desinstalacion

Bundle:

```bash
cd linux/dist/<distro>
sudo ./uninstall.sh
```

Paquete `.deb`:

```bash
sudo dpkg -r vant-siem-agent-<distro>
```

La guia detallada del layout offline vive en [OFFLINE_PACKAGING.md](./OFFLINE_PACKAGING.md).
