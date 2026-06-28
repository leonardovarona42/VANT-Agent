"""
Build script para VANT-Agent Linux (offline)
Compila a binario estatico con PyInstaller, o genera .deb offline
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _here():
    return Path(__file__).resolve().parent


def _root():
    return _here().parent


def _vendor_dir():
    d = _root() / "vendor"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _check_deps():
    vendor = _vendor_dir()
    wheels = list(vendor.glob("*.whl")) + list(vendor.glob("*.tar.gz"))
    if wheels:
        print(f"Usando {len(wheels)} paquetes desde vendor/")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--no-index", "--find-links", str(vendor),
            "-r", str(_here() / "requirements.txt"),
        ])
    else:
        print("AVISO: vendor/ vacio, instalando desde internet...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r",
            str(_here() / "requirements.txt"),
        ])


def _build_pyinstaller():
    try:
        import PyInstaller
        print(f"  + PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("  ! Instalando PyInstaller...")
        _check_deps_pyi()

    for d in ["build", "dist", "__pycache__"]:
        p = _here() / d
        if p.exists():
            shutil.rmtree(p)

    agent_py = _here() / "agent.py"
    config = _here() / "config.yaml"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "vant-agent",
        "--onefile",
        "--clean",
        "--distpath", str(_here() / "dist"),
        "--workpath", str(_here() / "build"),
        "--specpath", str(_here()),
        "--add-data", f"{config};config.yaml",
    ]
    hidden = [
        "yaml", "requests", "PIL", "pypdf", "docx", "openpyxl",
        "pptx", "odf", "olefile",
        "vant", "vant.main", "vant.api", "vant.config", "vant.utils",
        "vant.modules",
        "vant.modules.collectors", "vant.modules.collectors.base",
        "vant.modules.collectors.file_log",
        "vant.modules.collectors.postgres_log",
        "vant.modules.collectors.suricata",
        "vant.modules.collectors.snort",
        "vant.modules.inventory", "vant.modules.inventory.collector",
        "vant.modules.inventory.service",
        "vant.modules.heartbeat", "vant.modules.heartbeat.service",
        "vant.modules.dlp", "vant.modules.dlp.aegis",
    ]
    for mod in hidden:
        cmd.extend(["--hidden-import", mod])
    cmd.append(str(agent_py))

    print(f"\nEjecutando PyInstaller...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        binary = _here() / "dist" / "vant-agent"
        if binary.exists():
            size_mb = binary.stat().st_size / (1024 * 1024)
            print(f"\n  + Binario: {binary} ({size_mb:.1f} MB)")
            print("\n  COMPLETADO")
        else:
            print(f"\n  ! ERROR: binario no encontrado")
            print(result.stderr[-1000:])
    else:
        print(f"\n  ! ERROR de compilacion:")
        print(result.stderr[-2000:])
        sys.exit(1)


def _build_deb():
    """Genera paquete .deb offline con el agente empaquetado."""
    deb_dir = _here() / "dist" / "vant-agent-deb"
    deb_dir.mkdir(parents=True, exist_ok=True)

    # Estructura del .deb
    dirs = [
        "DEBIAN",
        "opt/vant-siem-agent",
        "opt/vant-siem-agent/collectors",
        "opt/vant-siem-agent/modules",
        "etc/vant-siem",
        "etc/systemd/system",
        "usr/local/bin",
    ]
    for d in dirs:
        (deb_dir / d).mkdir(parents=True, exist_ok=True)

    # Copiar codigo fuente
    shutil.copytree(str(_root() / "vant"), str(deb_dir / "opt/vant-siem-agent/vant"),
                    dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(str(_here() / "agent.py"), str(deb_dir / "opt/vant-siem-agent/agent.py"))
    shutil.copy2(str(_here() / "config.yaml"), str(deb_dir / "etc/vant-siem/config.yaml"))

    # Crear wrapper binario
    wrapper = deb_dir / "usr/local/bin/vant-agent"
    wrapper.write_text("#!/bin/bash\ncd /opt/vant-siem-agent && exec /usr/bin/python3 agent.py --config /etc/vant-siem/config.yaml \"$@\"\n")
    wrapper.chmod(0o755)

    # systemd service
    svc = deb_dir / "etc/systemd/system/vant-siem-agent.service"
    svc.write_text("""[Unit]
Description=VANT-SIEM Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vant-agent
Restart=on-failure
RestartSec=10
User=root
WorkingDirectory=/opt/vant-siem-agent

[Install]
WantedBy=multi-user.target
""")

    # control DEBIAN
    control = deb_dir / "DEBIAN/control"
    control.write_text("""Package: vant-siem-agent
Version: 1.1.0
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.8), python3-yaml, python3-requests, python3-pil
Maintainer: VANT-SIEM <dev@vant-siem.cu>
Description: VANT-SIEM Endpoint Agent
 Recolecta inventario de hardware, software y logs
 para el servidor VANT-SIEM.
""")

    # postinst
    postinst = deb_dir / "DEBIAN/postinst"
    postinst.write_text("""#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable vant-siem-agent
    systemctl start vant-siem-agent || true
fi
exit 0
""")
    postinst.chmod(0o755)

    # prerm
    prerm = deb_dir / "DEBIAN/prerm"
    prerm.write_text("""#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop vant-siem-agent || true
    systemctl disable vant-siem-agent || true
fi
exit 0
""")
    prerm.chmod(0o755)

    print(f"\n  + Estructura .deb creada en {deb_dir}")
    print(f"  + Para compilar el .deb ejecuta:")
    print(f"      dpkg-deb --build {deb_dir}")
    print(f"\n  COMPLETADO: paquete .deb listo para distribucion offline")


if __name__ == "__main__":
    if "--deb" in sys.argv:
        _build_deb()
    elif "--clean" in sys.argv:
        for d in ["build", "dist", "__pycache__"]:
            p = _here() / d
            if p.exists():
                shutil.rmtree(p)
                print(f"  + Limpiado: {d}/")
    else:
        _build_pyinstaller()
