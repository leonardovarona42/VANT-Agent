"""
Build script para VANT-Agent Windows (offline)
Compila a .exe usando PyInstaller sin conexion a internet
Requiere: pip install pyinstaller (pre-descargado en vendor/)
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
    """Verifica que las dependencias esten instaladas, usando vendor si es posible."""
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
        print("Sugerencia: descarga los wheels con:")
        print(f"  pip download -r {_here() / 'requirements.txt'} -d {vendor}")


def _clean():
    for d in ["build", "dist", "__pycache__"]:
        p = _here() / d
        if p.exists():
            shutil.rmtree(p)
            print(f"  + Limpiado: {d}/")
    for spec in _here().parent.glob("*.spec"):
        spec.unlink()


def _build():
    print("=== VANT-Agent Windows Builder (offline) ===\n")

    try:
        import PyInstaller
        print(f"  + PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("  ! Instalando PyInstaller...")
        vendor = _vendor_dir()
        pyi_wheels = list(vendor.glob("pyinstaller-*.whl"))
        if pyi_wheels:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install",
                "--no-index", "--find-links", str(vendor),
                str(pyi_wheels[0]),
            ])
        else:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "pyinstaller",
            ])

    _check_deps()
    _clean()

    agent_py = _root() / "windows" / "agent.py"
    icon = _root() / "vant.ico"
    config = _here() / "config.yaml"
    example_config = _root() / "config.example.yaml"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "VANT-Agent",
        "--onefile",
        "--windowed",
        "--clean",
        "--distpath", str(_here() / "dist"),
        "--workpath", str(_here() / "build"),
        "--specpath", str(_here()),
        "--add-data", f"{config};.",
    ]
    if icon.exists():
        cmd.extend(["--icon", str(icon)])

    hidden = [
        "yaml", "requests", "PIL", "pypdf", "docx", "openpyxl",
        "pptx", "odf", "olefile",
        "vant", "vant.main", "vant.api", "vant.config", "vant.utils",
        "vant.modules",
        "vant.modules.collectors", "vant.modules.collectors.base",
        "vant.modules.collectors.file_log",
        "vant.modules.collectors.windows_eventlog",
        "vant.modules.collectors.postgres_log",
        "vant.modules.collectors.suricata",
        "vant.modules.collectors.snort",
        "vant.modules.inventory", "vant.modules.inventory.collector",
        "vant.modules.inventory.service",
        "vant.modules.heartbeat", "vant.modules.heartbeat.service",
        "vant.modules.dlp", "vant.modules.dlp.aegis",
        "vant.modules.screen", "vant.modules.screen.service",
    ]
    for mod in hidden:
        cmd.extend(["--hidden-import", mod])

    excluded = ["pytest", "setuptools", "unittest", "tkinter"]
    for mod in excluded:
        cmd.extend(["--exclude-module", mod])

    cmd.append(str(agent_py))

    print(f"\nEjecutando PyInstaller...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        exe = _here() / "dist" / "VANT-Agent.exe"
        if exe.exists():
            size_mb = exe.stat().st_size / (1024 * 1024)
            print(f"\n  + EXE compilado: {exe} ({size_mb:.1f} MB)")
            config_dst = _here() / "dist" / "config.yaml"
            if config.exists() and not config_dst.exists():
                shutil.copy2(config, config_dst)
                print(f"  + config.yaml copiado a dist/")
            print("\n  COMPLETADO: VANT-Agent.exe listo para distribuir")
        else:
            print("\n  ! ERROR: EXE no encontrado en dist/")
            print(result.stderr[-1000:])
    else:
        print("\n  ! ERROR de compilacion:")
        print(result.stderr[-2000:])
        sys.exit(1)


if __name__ == "__main__":
    if "--clean" in sys.argv:
        _clean()
    else:
        _build()
