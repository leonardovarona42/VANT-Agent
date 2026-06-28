# VANT-Agent para Linux

Recolecta inventario de hardware, software, informacion del cliente
y logs (Snort, Suricata, PostgreSQL, archivos) para el servidor VANT-SIEM.

## Requisitos

- Ubuntu 22.04+/Debian 12+/RHEL 9+
- Python 3.8+
- Para Snort/Suricata: tener los servicios instalados

## Instalacion desde codigo fuente

```
# Opcion 1: Con internet
pip install -r requirements.txt
python agent.py --config config.yaml

# Opcion 2: Sin internet (offline)
pip install --no-index --find-links=../vendor -r requirements.txt
python agent.py --config config.yaml
```

## Compilar a binario estatico (offline)

```
python build_agent.py
```

## Generar paquete .deb offline

```
python build_agent.py --deb
dpkg-deb --build dist/vant-agent-deb
```

## Instalar .deb

```
sudo dpkg -i vant-agent-deb.deb
sudo systemctl start vant-siem-agent
```

## Preparar dependencias offline

En una maquina con internet:
```
pip download -r requirements.txt -d ../vendor
```

Luego copia `vendor/` a la maquina offline.

## Estructura

```
linux/
  agent.py              Entry point principal
  config.yaml           Configuracion por defecto
  build_agent.py        Script de compilacion (.deb + binario)
  requirements.txt      Dependencias
  README.md             Este archivo
```
