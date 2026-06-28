"""
VANT-Agent para Linux
Entry point optimizado que usa el modulo compartido vant/
Recolecta: inventario HW/SW, informacion del cliente, logs (snort, suricata, postgres, archivos)
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
    paths = [
        "/etc/vant-siem/config.yaml",
        "/opt/vant-siem-agent/config.yaml",
        str(Path(__file__).resolve().parent / "config.yaml"),
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return paths[-1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VANT-Agent Linux")
    parser.add_argument("--config", default=default_config_path())
    parser.add_argument("--tray", action="store_true")
    parser.add_argument("--monitor-only", action="store_true")
    args = parser.parse_args()

    if args.tray:
        from vant.tray import main as tray_main
        sys.argv = [sys.argv[0], "--config", args.config]
        if args.monitor_only:
            sys.argv.append("--monitor-only")
        tray_main()
    else:
        print(f"VANT-Agent Linux v1.1.0")
        print(f"Config: {args.config}")
        run(args.config)
