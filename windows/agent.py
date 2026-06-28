"""
VANT-Agent para Windows
Entry point optimizado que usa el modulo compartido vant/
Recolecta: inventario HW/SW, informacion del cliente, logs de eventos
"""
import argparse
import os
import sys
from pathlib import Path


def _add_paths():
    base = Path(__file__).resolve().parent.parent
    for p in [str(base), str(base / "vant")]:
        if p not in sys.path:
            sys.path.insert(0, p)


_add_paths()

from vant.main import run, run_with_stop, main


def default_config_path():
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent / "config.yaml")
    return str(Path(__file__).resolve().parent / "config.yaml")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VANT-Agent Windows")
    parser.add_argument("--config", default=default_config_path())
    parser.add_argument("--tray", action="store_true", help="Bandeja del sistema")
    parser.add_argument("--monitor-only", action="store_true")
    args = parser.parse_args()

    if args.tray:
        from vant.tray import main as tray_main
        sys.argv = [sys.argv[0], "--config", args.config]
        if args.monitor_only:
            sys.argv.append("--monitor-only")
        tray_main()
    else:
        print(f"VANT-Agent Windows v1.1.0")
        print(f"Config: {args.config}")
        run(args.config)
