#!/usr/bin/env python3
import argparse
import socket
import subprocess
import sys
from pathlib import Path

import requests
import yaml


def load_cfg(path):
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config file not found: {cfg_path}")
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}


def _get_local_ips():
    ips = set()
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    try:
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
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                ips.add(sock.getsockname()[0])
        except Exception:
            pass
    return [ip for ip in ips if ip and not ip.startswith("127.")]


def detect_host():
    hostname = socket.gethostname()
    ips = _get_local_ips()
    ip = ips[0] if ips else ""
    return hostname, ip


def current_ips():
    return _get_local_ips()


def default_config_path():
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent / "config.yaml")
    return "config.yaml"


def main():
    parser = argparse.ArgumentParser(description="Send one manual heartbeat for the VANT-SIEM agent.")
    parser.add_argument("--config", default=default_config_path(), help="Path to config.yaml")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    args = parser.parse_args()

    cfg = load_cfg(args.config)
    agent_cfg = cfg.get("agent", {}) or {}
    control_cfg = cfg.get("control", {}) or {}
    output_cfg = cfg.get("output", {}) or {}
    server_url = (control_cfg.get("server_url") or "").rstrip("/")
    token = (
        (output_cfg.get("auth") or {}).get("token")
        or control_cfg.get("token")
        or ""
    )

    if not server_url:
        raise SystemExit("control.server_url is not configured")
    if not token:
        raise SystemExit("No control token found in configuration")

    host_name, host_ip = detect_host()
    payload = {
        "agent_id": agent_cfg.get("id", ""),
        "host_name": agent_cfg.get("host_name") or host_name,
        "host_ip": host_ip,
        "agent_version": "manual-heartbeat",
        "ips": current_ips(),
    }
    url = f"{server_url}/api/agent/heartbeat/"
    response = requests.post(
        url,
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=args.timeout,
    )
    print(f"heartbeat_url={url}")
    print(f"status_code={response.status_code}")
    print(response.text)
    if response.status_code != 200:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
