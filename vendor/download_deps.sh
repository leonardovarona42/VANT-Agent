#!/bin/bash
# Descarga todas las dependencias para compilacion offline
# Ejecutar en una maquina con internet y copiar vendor/ al destino offline

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Descargando dependencias offline ==="

# Windows
echo ""
echo "--- Dependencias Windows ---"
pip download -r "$SCRIPT_DIR/../windows/requirements.txt" -d "$SCRIPTDIR" --platform win_amd64 --python-version 3.12 --only-binary=:all: 2>/dev/null || \
pip download -r "$SCRIPT_DIR/../windows/requirements.txt" -d "$SCRIPTDIR"

# Linux
echo ""
echo "--- Dependencias Linux ---"
pip download -r "$SCRIPT_DIR/../linux/requirements.txt" -d "$SCRIPTDIR" --platform manylinux_2_28_x86_64 --python-version 3.12 --only-binary=:all: 2>/dev/null || \
pip download -r "$SCRIPT_DIR/../linux/requirements.txt" -d "$SCRIPTDIR"

# PyInstaller (para ambas plataformas)
echo ""
echo "--- PyInstaller ---"
pip download pyinstaller -d "$SCRIPTDIR" 2>/dev/null || true

echo ""
echo "=== Descarga completada ==="
echo "Wheels guardados en: $SCRIPTDIR"
echo "Total: $(ls -1 "$SCRIPTDIR"/*.whl 2>/dev/null | wc -l) paquetes"
