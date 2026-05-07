import logging
import os
import socket
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def detect_host():
    hostname = socket.gethostname()
    ip = ""
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        pass
    if ip.startswith("127.") or not ip:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
        except Exception:
            pass
    return hostname, ip


def get_current_ips():
    ips = set()
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    return [ip for ip in ips if ip and not ip.startswith("127.")]


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

    sh = logging.StreamHandler(sys.stdout)
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
