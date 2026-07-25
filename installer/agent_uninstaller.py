"""
VANT-Agent Uninstaller
Removes agent files, scheduled task, shortcuts, and state.
Run as Administrator: Right-click -> Run as Administrator
"""
import os
import sys
import subprocess
import ctypes
import shutil
from pathlib import Path


def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def _run_ps(cmd):
    subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, timeout=15,
    )


def uninstall(install_dir):
    print("Stopping VANT-Agent process...")
    _run_ps("Get-Process -Name VANT-Agent -ErrorAction SilentlyContinue | Stop-Process -Force")

    print("Removing scheduled task...")
    subprocess.run(
        ["schtasks", "/Delete", "/TN", "VANT-SIEM-Agent", "/F"],
        capture_output=True, timeout=10,
    )

    print("Removing desktop shortcut...")
    desktop = Path(os.environ.get("USERPROFILE", "")) / "Desktop" / "VANT-Agent.lnk"
    if desktop.exists():
        desktop.unlink()

    print(f"Deleting {install_dir}...")
    path = Path(install_dir)
    if path.exists():
        shutil.rmtree(str(path))

    print("Uninstall complete!")


if __name__ == "__main__":
    if not _is_admin():
        try:
            script = sys.argv[0]
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}"', None, 1
            )
            sys.exit(0)
        except Exception:
            print("ERROR: Administrator privileges required.")
            print("Right-click the script and select 'Run as Administrator'.")
            sys.exit(1)

    if len(sys.argv) > 1:
        install_dir = sys.argv[1]
    else:
        install_dir = r"C:\Program Files\VANT-Agent"

    uninstall(install_dir)
