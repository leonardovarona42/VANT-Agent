# VANT-Agent para Windows

Recolecta inventario de hardware, software, informacion del cliente
y logs de Eventos de Windows para el servidor VANT-SIEM.

## Requisitos

- Windows 10/11 o Windows Server 2019/2022/2025
- Python 3.10+ (para desarrollo)
- PowerShell 5.1+

## Instalacion desde codigo fuente

```
# Opcion 1: Con internet
pip install -r requirements.txt
python agent.py --config config.yaml

# Opcion 2: Sin internet (offline)
pip install --no-index --find-links=../vendor -r requirements.txt
python agent.py --config config.yaml
```

## Compilar a .exe (offline)

```
python build_agent.py
```

Esto genera `dist/VANT-Agent.exe` listo para distribuir.

## Preparar dependencias offline

En una maquina con internet:
```
pip download -r requirements.txt -d ../vendor
pip download pyinstaller -d ../vendor
```

Luego copia `vendor/` a la maquina offline.

## Estructura

```
windows/
  agent.py              Entry point principal
  config.yaml           Configuracion por defecto
  build_agent.py        Script de compilacion offline
  requirements.txt      Dependencias
  README.md             Este archivo
```
