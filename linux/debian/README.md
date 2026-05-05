# Debian Agent Pack

## 1) Instalar agente

### Opcion A: bundle offline

Con GUI:

```bash
cd opensearch_agents/linux/dist/debian
sudo ./install.sh
```

Sin GUI o servidor headless:

```bash
cd opensearch_agents/linux/dist/debian
sudo ./install.sh --gdisable
```

### Opcion B: paquete `.deb`

Normal:

```bash
sudo dpkg -i opensearch_agents/linux/dist/vant-siem-agent-debian_1.0.0_all.deb
```

Headless:

```bash
sudo VANT_AGENT_GDISABLE=1 dpkg -i opensearch_agents/linux/dist/vant-siem-agent-debian_1.0.0_all.deb
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

Ese flujo deja el comportamiento alineado con el instalador de Windows: al
probar la conexion intenta enrolar el agente automaticamente.

Si necesitas desactivar el asistente:

```bash
sudo VANT_AGENT_WIZARD=0 ./install.sh --gdisable
sudo VANT_AGENT_WIZARD=0 VANT_AGENT_GDISABLE=1 dpkg -i opensearch_agents/linux/dist/vant-siem-agent-debian_1.0.0_all.deb
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

## 5) Habilitar fuentes de logs

```bash
cd opensearch_agents/linux/debian
sudo ./enable_logs.sh
```

### Snort

1. En `snort.conf`, habilitar `alert_fast` a archivo:

```conf
output alert_fast: /var/log/snort/alert
```

2. Reiniciar el servicio:

```bash
sudo systemctl restart snort
```

### Suricata

1. En `/etc/suricata/suricata.yaml`, validar:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
```

2. Reiniciar:

```bash
sudo systemctl restart suricata
```

### PostgreSQL

1. Editar `postgresql.conf`:

```conf
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_statement = 'all'
```

2. Reiniciar PostgreSQL.
3. Ajustar `collectors.postgres.path` al archivo real en `/var/log/postgresql/`.

### Samba (si aplica)

1. Habilitar `vfs_full_audit` en `smb.conf` para escribir auditoria.
2. Enviar a `/var/log/samba/audit.log`.
3. Agregar en `collectors.file_logs.items` una entrada para ese archivo.

## 6) Estado del servicio

```bash
sudo systemctl status vant-siem-agent
sudo journalctl -u vant-siem-agent -f
```
