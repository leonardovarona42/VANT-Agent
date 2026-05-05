import ctypes
import subprocess
import sys
from pathlib import Path


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def parse_args(argv):
    user_mode = False
    no_prompt = False
    install_dir = None
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--user-mode":
            user_mode = True
        elif arg == "--noprompt":
            no_prompt = True
        elif arg == "--install-dir" and i + 1 < len(argv):
            install_dir = argv[i + 1]
            i += 1
        i += 1
    return user_mode, no_prompt, install_dir


def main():
    exe_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    script_path = exe_dir / "Uninstall-OpenSearchAgent.ps1"
    user_mode, no_prompt, install_dir = parse_args(sys.argv[1:])

    if not script_path.exists():
        print(f"No se encontro el desinstalador PowerShell: {script_path}")
        return 1

    args = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
    ]
    if user_mode:
        args.append("-UserMode")
    if install_dir:
        args.extend(["-InstallDir", install_dir])

    if not user_mode and not is_admin():
        params = " ".join(f'"{part}"' if " " in part else part for part in args[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", args[0], params, None, 1)
        return 0 if rc > 32 else int(rc)

    completed = subprocess.run(args, check=False)
    if completed.returncode != 0 and not no_prompt:
        print("La desinstalacion fallo.")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
