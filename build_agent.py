#!/usr/bin/env python3
"""
VANT-Agent Build Script (PyInstaller)
Builds standalone executable from the new modular structure.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

AGENT_VERSION = "1.1.0"


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header(title):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}  {title}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}\n")


def print_ok(msg):
    print(f"  {Colors.GREEN}+{Colors.END} {msg}")


def print_err(msg):
    print(f"  {Colors.RED}x{Colors.END} {msg}")


def print_warn(msg):
    print(f"  {Colors.YELLOW}!{Colors.END} {msg}")


def print_info(msg):
    print(f"  {Colors.BLUE}>{Colors.END} {msg}")


def clean():
    print_info("Cleaning previous builds...")
    script_dir = Path(__file__).parent
    for d in ['build', 'dist', '__pycache__']:
        p = script_dir / d
        if p.exists():
            shutil.rmtree(p)
            print_ok(f"Removed: {d}/")
    for spec in script_dir.glob('*.spec'):
        spec.unlink()
        print_ok(f"Removed: {spec.name}")


def build():
    print_header(f"VANT-Agent v{AGENT_VERSION} Builder")

    # Check deps
    dep_map = {'yaml': 'pyyaml', 'requests': 'requests'}
    for mod, pkg in dep_map.items():
        try:
            __import__(mod)
            print_ok(f"{mod}: installed")
        except ImportError:
            print_warn(f"{mod}: installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

    try:
        import PyInstaller
        print_ok(f"PyInstaller: {PyInstaller.__version__}")
    except ImportError:
        print_warn("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    try:
        import PyQt6
        print_ok(f"PyQt6: installed")
    except ImportError:
        print_warn("Installing PyQt6...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyQt6"])

    clean()

    print_header("Building VANT-Agent")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "VANT-Agent",
        "--onefile",
        "--console",
        "--clean",
        "--add-data", "config.example.yaml;.",
        "--hidden-import", "yaml",
        "--hidden-import", "requests",
        "--hidden-import", "vant",
        "--hidden-import", "vant.main",
        "--hidden-import", "vant.modules.inventory.collector",
        "--hidden-import", "vant.modules.inventory.service",
        "--hidden-import", "vant.modules.heartbeat.service",
        "--hidden-import", "vant.modules.collectors.file_log",
        "--hidden-import", "vant.modules.collectors.windows_eventlog",
        "--hidden-import", "vant.modules.collectors.postgres_log",
        "--hidden-import", "vant.modules.collectors.suricata",
        "--hidden-import", "vant.modules.collectors.snort",
        "--hidden-import", "vant.modules.dlp.aegis",
        "--exclude-module", "pytest",
        "--exclude-module", "setuptools",
        "run.py",
    ]

    print_info(f"Running: {' '.join(cmd[:5])}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        exe = Path("dist") / "VANT-Agent.exe"
        if exe.exists():
            size_mb = exe.stat().st_size / (1024 * 1024)
            print_ok(f"VANT-Agent.exe built ({size_mb:.1f} MB)")

            # Copy config
            config_src = Path("config.example.yaml")
            config_dst = Path("dist") / "config.yaml"
            if config_src.exists() and not config_dst.exists():
                shutil.copy2(config_src, config_dst)
                print_ok("config.yaml copied to dist/")

            print_header("Build Complete")
            print_ok(f"Output: {exe.resolve()}")
            print()
            print_info("To run: VANT-Agent.exe --config config.yaml")
        else:
            print_err("Build succeeded but exe not found")
    else:
        print_err("Build failed")
        print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
        sys.exit(1)


if __name__ == '__main__':
    if '--clean' in sys.argv:
        clean()
    else:
        build()
