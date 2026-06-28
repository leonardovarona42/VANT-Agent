import logging
import os
import socket
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _hide_window():
    kwargs = {}
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        kwargs["startupinfo"] = si
    return kwargs


def popen_hidden(*args, **kwargs):
    kwargs.update(_hide_window())
    return subprocess.Popen(*args, **kwargs)


def run_hidden(*args, **kwargs):
    kwargs.update(_hide_window())
    return subprocess.run(*args, **kwargs)


def check_output_hidden(*args, **kwargs):
    kwargs.update(_hide_window())
    return subprocess.check_output(*args, **kwargs)


def _get_local_ips():
    """Obtiene IPs locales sin depender de internet."""
    ips = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if socket.AF_INET in addrs:
                for addr in addrs[socket.AF_INET]:
                    ip = addr.get('addr', '')
                    if ip and not ip.startswith("127."):
                        ips.add(ip)
    except ImportError:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.connect(("8.8.8.8", 80))
                ips.add(s.getsockname()[0])
        except Exception:
            pass
        try:
            import subprocess, sys
            if sys.platform.startswith("win"):
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*'}).IPAddress"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                for line in out.stdout.strip().splitlines():
                    ip = line.strip()
                    if ip and not ip.startswith("127."):
                        ips.add(ip)
            else:
                out = subprocess.run(
                    ["ip", "-4", "addr", "show"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                for line in out.stdout.splitlines():
                    if "inet " in line:
                        ip = line.strip().split()[1].split("/")[0]
                        if ip and not ip.startswith("127."):
                            ips.add(ip)
        except Exception:
            pass
    return [ip for ip in ips if ip and not ip.startswith("127.")]


def detect_host():
    hostname = socket.gethostname()
    ips = _get_local_ips()
    ip = ips[0] if ips else ""
    return hostname, ip


def get_current_ips():
    return _get_local_ips()


def configure_logging(cfg, config_path):
    level_name = str(cfg.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    log_file = cfg.get("file", "")
    if not log_file:
        if sys.platform.startswith("linux"):
            log_file = "/var/log/vant-agent/agent.log"
        else:
            log_file = str(Path(sys.executable).resolve().parent / "vant-agent.log")

    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("vant-agent")
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    max_bytes = int(cfg.get("max_bytes", 10 * 1024 * 1024))
    backup_count = int(cfg.get("backup_count", 5))
    fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    fh.setFormatter(fmt)
    fh.setLevel(level)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh.setLevel(level)
    logger.addHandler(sh)

    return logger


def sleep_with_stop(stop_event, seconds):
    remaining = max(0, int(seconds))
    while remaining > 0:
        if stop_event.is_set():
            return
        import time
        time.sleep(1)
        remaining -= 1


def detect_os():
    import platform
    system = platform.system().lower()
    if system == "windows":
        version = platform.version()
        if "10.0." in version:
            try:
                build = int(version.split(".")[-1])
                if build >= 22000:
                    return "windows_11"
            except Exception:
                pass
        release = platform.release()
        if "11" in release:
            return "windows_11"
        if "Server" in platform.win32_ver()[2] or "server" in platform.version().lower():
            if "2025" in platform.win32_ver()[2]:
                return "windows_server_2025"
            if "2022" in platform.win32_ver()[2]:
                return "windows_server_2022"
            if "2019" in platform.win32_ver()[2]:
                return "windows_server_2019"
        return "windows_10"
    if system == "linux":
        try:
            with open("/etc/os-release") as f:
                content = f.read()
            if "ubuntu" in content.lower():
                return "ubuntu_24_04"
            if "debian" in content.lower():
                return "debian_12"
            if "rhel" in content.lower():
                return "rhel_9"
            if "centos" in content.lower():
                return "centos_9"
        except Exception:
            pass
        return "other_linux"
    if system == "darwin":
        return "macos_15"
    return "other"


def get_mac_address():
    import platform
    if platform.system() == "Windows":
        try:
            out = check_output_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.MacAddress -ne $null} | Select-Object -First 1).MacAddress"],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
            if out and ":" in out:
                return out.upper()
        except Exception:
            pass
        try:
            import uuid
            mac = uuid.getnode()
            return ":".join(["{:02x}".format((mac >> i) & 0xff).upper() for i in range(0, 8 * 6, 8)][::-1])
        except Exception:
            pass
    else:
        try:
            for iface in os.listdir("/sys/class/net"):
                if iface == "lo":
                    continue
                addr_file = f"/sys/class/net/{iface}/address"
                if os.path.isfile(addr_file):
                    with open(addr_file) as f:
                        mac = f.read().strip().upper()
                        if mac and ":" in mac:
                            return mac
        except Exception:
            pass
    return ""
