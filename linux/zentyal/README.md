# Zentyal Agent Pack (Samba AD)

## 1) Instalar agente

### Opcion A: bundle offline

Con GUI:

```bash
cd opensearch_agents/linux/dist/zentyal
sudo ./install.sh
```

Sin GUI o servidor headless:

```bash
cd opensearch_agents/linux/dist/zentyal
sudo ./install.sh --gdisable
```

### Opcion B: paquete `.deb`

Normal:

```bash
sudo dpkg -i opensearch_agents/linux/dist/vant-siem-agent-zentyal_1.0.0_all.deb
```

Headless:

```bash
sudo VANT_AGENT_GDISABLE=1 dpkg -i opensearch_agents/linux/dist/vant-siem-agent-zentyal_1.0.0_all.deb
```

Config principal:

`/etc/vant-siem/config.yaml`

La maquina destino no necesita internet. El paquete ya incluye los binarios del
agente, el tray Linux, las herramientas operativas y los servicios necesarios.

## 2) Asistente y enrolamiento

Si instalas desde una terminal interactiva, el instalador abre el asistente CLI
para pedir:

1. Host y puerto del servidor de control.
2. Host y puerto del endpoint de eventos.
3. Metodo de autenticacion.
4. Prueba de conectividad.
5. Enrolamiento automatico durante la prueba.

Ese flujo replica el comportamiento del instalador de Windows: durante el test
de conexion intenta enrolar automaticamente el agente.

Si necesitas desactivar el asistente:

```bash
sudo VANT_AGENT_WIZARD=0 ./install.sh --gdisable
sudo VANT_AGENT_WIZARD=0 VANT_AGENT_GDISABLE=1 dpkg -i opensearch_agents/linux/dist/vant-siem-agent-zentyal_1.0.0_all.deb
```

Si el enrolamiento automatico falla, puedes completarlo despues:

```bash
sudo opena_enroll
sudo opena_enroll --enrollment-code CODIGO-DEL-TICKET
sudo opena_enroll --bootstrap-key MI-SECRETO-COMPARTIDO
```

## 3) GUI vs modo terminal

Modo normal:

1. Instala el servicio del agente.
2. Deja activo el tray GUI.
3. Crea `/etc/xdg/autostart/vant-siem-agent-tray.desktop`.

Modo `--gdisable` o `VANT_AGENT_GDISABLE=1`:

1. Instala el mismo servicio del agente.
2. No deja tray grafico.
3. Toda la administracion queda disponible por terminal.

## 4) Utilidades instaladas

Despues de instalar quedan disponibles en `/usr/local/bin`:

1. `sendheartbeat`
2. `opena_mover`
3. `opena_checker`
4. `opena_enroll`
5. `vant-agent-cli`

Ejemplos:

```bash
sudo opena_checker
sudo sendheartbeat
sudo opena_mover --host 192.168.12.43 --port 9201
```

## 5) Habilitar logs para AD Samba + extras

```bash
cd opensearch_agents/linux/zentyal
sudo ./enable_logs.sh
```

Este script:

1. Crea `/etc/samba/smb.conf.d/99-vant-audit.conf`.
2. Agrega include en `/etc/samba/smb.conf` si no existe.
3. Configura `rsyslog` para enviar `local5.notice` a `/var/log/samba/audit.log`.
4. Reinicia `rsyslog` y `samba-ad-dc` o `smbd`.

## 6) Consideracion importante de Zentyal

Zentyal puede regenerar configuraciones Samba. Si eso pasa:

1. Reaplica `enable_logs.sh`.
2. O mueve estos ajustes a plantillas persistentes de Zentyal.

## 7) Otras fuentes

### PostgreSQL

1. Habilitar `logging_collector = on` en `postgresql.conf`.
2. Ajustar `collectors.postgres.path`.

### Snort/Suricata

1. Snort hacia `/var/log/snort/alert`.
2. Suricata `eve.json` en `/var/log/suricata/eve.json`.
3. Activar en `config.yaml`.

## 8) Verificar

```bash
sudo systemctl status vant-siem-agent
sudo journalctl -u vant-siem-agent -f
tail -f /var/log/samba/audit.log
```
