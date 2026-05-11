#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_AGENT_SHARED_SECRET = "VANT-SIEM-AGENT-BOOTSTRAP-2026"


def _default_config_paths():
    candidates = []
    env_path = os.environ.get("VANT_AGENT_CONFIG", "").strip()
    if env_path:
        candidates.append(Path(env_path))
    candidates.extend(
        [
            Path("/etc/vant-siem/config.yaml"),
            Path(__file__).resolve().parents[1] / "config" / "agent.yaml",
            Path(__file__).resolve().parents[2] / "config.yaml",
        ]
    )
    return candidates


def load_config(config_path=None):
    paths = [Path(config_path)] if config_path else _default_config_paths()
    for path in paths:
        if path.exists():
            return yaml.safe_load(path.read_text(encoding="utf-8")) or {}, path
    raise FileNotFoundError("Config file not found")


def save_config(config, config_path):
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=False), encoding="utf-8")


def _resolve_service_root():
    candidates = [
        Path("/opt/vant-siem-agent"),
        Path(__file__).resolve().parents[1],
    ]
    for candidate in candidates:
        if (candidate / "scripts" / "agent_tools.py").exists() or (candidate / "agent" / "venv" / "bin" / "python").exists():
            return candidate
    return Path(__file__).resolve().parents[1]


def _python_exec():
    root = _resolve_service_root()
    for candidate in [
        root / "venv" / "bin" / "python",
        root / "agent" / "venv" / "bin" / "python",
    ]:
        if candidate.exists():
            return candidate
    return Path(sys.executable)


def _api_url(config):
    control = config.get("control", {}) or {}
    return (control.get("server_url") or "").rstrip("/")


def _auth_headers(config):
    token = (config.get("output", {}) or {}).get("auth", {}).get("token", "")
    if token:
        return {"Authorization": f"Bearer {token}"}
    control_token = (config.get("control", {}) or {}).get("token", "")
    if control_token:
        return {"Authorization": f"Bearer {control_token}"}
    return {}


def _verify_ssl(config):
    control = config.get("control", {}) or {}
    verify = control.get("verify_ssl", True)
    if isinstance(verify, bool):
        return verify
    return str(verify).lower() in ("1", "true", "yes")


def _build_bootstrap_url(config):
    server_url = _api_url(config)
    return f"{server_url}/inventory/api/agent/bootstrap/" if server_url else ""


def _build_enroll_url(config):
    server_url = _api_url(config)
    return f"{server_url}/inventory/api/agent/enroll/" if server_url else ""


def _owner_account():
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    user = sudo_user or os.environ.get("USER", "").strip() or os.environ.get("USERNAME", "").strip()
    if not user:
        return ""
    return user


def _build_enrollment_payload(config, shared_secret, enrollment_code=""):
    agent = config.setdefault("agent", {})
    agent_id = agent.get("id", "agent")
    host_name = agent.get("host_name") or socket.gethostname()
    timestamp = str(int(time.time()))
    payload = {
        "agent_id": agent_id,
        "host_name": host_name,
        "timestamp": timestamp,
        "signature": _sign_enrollment(shared_secret, agent_id, host_name, timestamp),
        "install_owner_account": _owner_account(),
    }
    if enrollment_code:
        payload["enrollment_code"] = enrollment_code
    return payload


def _load_bootstrap_key(override=""):
    if override:
        return override.strip()
    env_key = os.environ.get("VANT_AGENT_BOOTSTRAP_KEY", "").strip()
    if env_key:
        return env_key
    env_shared = os.environ.get("VANT_AGENT_SHARED_SECRET", "").strip()
    if env_shared:
        return env_shared
    return ""


def _fetch_bootstrap_secret(config, agent_id):
    url = _build_bootstrap_url(config)
    if not url:
        return ""
    try:
        response = requests.get(
            url,
            headers={"X-Agent-Id": agent_id},
            timeout=8,
            verify=_verify_ssl(config),
        )
        if "application/json" not in response.headers.get("Content-Type", ""):
            return ""
        data = response.json()
        if response.status_code == 200 and data.get("ok") and data.get("secret"):
            return data.get("secret", "")
    except Exception:
        return ""
    return ""


def _sign_enrollment(secret, agent_id, host_name, timestamp):
    message = f"{agent_id}:{host_name}:{timestamp}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _current_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ips.add(sock.getsockname()[0])
    except Exception:
        pass
    return [ip for ip in ips if ip and not ip.startswith("127.")]


def _detect_host():
    hostname = socket.gethostname()
    ip = ""
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        pass
    if not ip or ip.startswith("127."):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                ip = sock.getsockname()[0]
        except Exception:
            ip = ""
    return hostname, ip


def send_heartbeat(config_path=None):
    config, resolved = load_config(config_path)
    control = config.get("control", {}) or {}
    server_url = (control.get("server_url") or "").rstrip("/")
    if not server_url:
        raise SystemExit("control.server_url not configured")
    agent = config.get("agent", {}) or {}
    payload = {
        "agent_id": agent.get("id", "agent"),
        "host_name": agent.get("host_name") or socket.gethostname(),
        "host_ip": agent.get("host_ip", ""),
        "agent_version": agent.get("version", "linux"),
        "ips": _current_ips(),
        "source": "manual-heartbeat",
    }
    response = requests.post(
        f"{server_url}/api/agent/heartbeat/",
        json=payload,
        headers=_auth_headers(config),
        timeout=8,
    )
    response.raise_for_status()
    print(f"Heartbeat sent from {payload['host_name']} via {resolved}")


def enroll_agent(config_path=None, bootstrap_key="", enrollment_code="", backup=True, quiet=False):
    config, resolved = load_config(config_path)
    server_url = _api_url(config)
    if not server_url:
        raise SystemExit("control.server_url not configured")

    output = config.setdefault("output", {})
    auth = output.setdefault("auth", {})
    agent = config.setdefault("agent", {})
    agent_id = agent.get("id", "agent")

    shared_secret = _load_bootstrap_key(bootstrap_key)
    if not shared_secret:
        shared_secret = _fetch_bootstrap_secret(config, agent_id)
    if not shared_secret:
        shared_secret = DEFAULT_AGENT_SHARED_SECRET

    payload = _build_enrollment_payload(config, shared_secret, enrollment_code)
    response = requests.post(_build_enroll_url(config), json=payload, timeout=8, verify=_verify_ssl(config))
    data = response.json() if "application/json" in response.headers.get("Content-Type", "") else {}
    if response.status_code != 200 or not data.get("ok") or not data.get("token"):
        error = data.get("error") or response.text or f"Enrollment failed with status {response.status_code}"
        raise SystemExit(error)

    server_agent_id = data.get("agent_id", "")
    if server_agent_id:
        agent["id"] = server_agent_id

    auth["mode"] = "token"
    auth["token"] = data.get("token", "")
    auth["username"] = ""
    auth["password"] = ""

    if backup:
        backup_path = resolved.with_suffix(".yaml.bak")
        backup_path.write_text(resolved.read_text(encoding="utf-8"), encoding="utf-8")
    save_config(config, resolved)

    if not quiet:
        print(f"Agent enrolled successfully via {server_url}")
        print(f"Config updated: {resolved}")
        print(f"Issued by: {data.get('issued_by', '')}")
    return data


def move_server(config_path=None, host=None, port=None, https=False, backup=True):
    config, resolved = load_config(config_path)
    output = config.setdefault("output", {})
    control = config.setdefault("control", {})
    if not host:
        raise SystemExit("A new host is required")
    if port is None:
        port = 9201 if https else 9200
    scheme = "https" if https else "http"
    output["endpoint"] = f"{scheme}://{host}:{port}/api/v1/events/bulk"
    output["source_endpoint"] = f"{scheme}://{host}:{port}/api/v1/sources/upsert"
    output.setdefault("tls", {})["enabled"] = bool(https)
    control["server_url"] = f"{scheme}://{host}:8000"
    control["require_https"] = bool(https)
    if backup:
        backup_path = resolved.with_suffix(".yaml.bak")
        backup_path.write_text(resolved.read_text(encoding="utf-8"), encoding="utf-8")
    save_config(config, resolved)
    print(f"Config updated in {resolved}")
    return resolved


def check_agent(config_path=None):
    config, resolved = load_config(config_path)
    agent = config.get("agent", {}) or {}
    output = config.get("output", {}) or {}
    control = config.get("control", {}) or {}
    endpoint = output.get("endpoint", "")
    server_url = (control.get("server_url") or "").rstrip("/")
    print(json.dumps(
        {
            "config": str(resolved),
            "agent_id": agent.get("id", ""),
            "host_name": agent.get("host_name", ""),
            "host_ip": agent.get("host_ip", ""),
            "endpoint": endpoint,
            "control_server": server_url,
            "token_present": bool(output.get("auth", {}).get("token") or control.get("token")),
            "agent_executable": str(_python_exec()),
        },
        indent=2,
    ))

    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.hostname and parsed.port:
            try:
                with socket.create_connection((parsed.hostname, parsed.port), timeout=4):
                    print(f"Endpoint reachable: {parsed.hostname}:{parsed.port}")
            except Exception as exc:
                print(f"Endpoint unreachable: {exc}")
    if server_url:
        try:
            response = requests.get(
                f"{server_url}/api/agent/bootstrap/",
                headers={"X-Agent-Id": agent.get("id", "")},
                timeout=8,
            )
            print(f"Bootstrap endpoint status: {response.status_code}")
        except Exception as exc:
            print(f"Bootstrap endpoint error: {exc}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="VANT-SIEM Linux operational utilities")
    parser.add_argument("--config", default="", help="Path to config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("heartbeat", help="Send a manual heartbeat")

    enroll = sub.add_parser("enroll", help="Enroll agent and store token in config")
    enroll.add_argument("--bootstrap-key", default="", help="Shared secret override for enrollment")
    enroll.add_argument("--enrollment-code", default="", help="Enrollment ticket/code if required by server")
    enroll.add_argument("--no-backup", action="store_true")
    enroll.add_argument("--quiet", action="store_true", help="Reduce output for unattended installs")

    move = sub.add_parser("move", help="Move agent to a new server")
    move.add_argument("--host", required=True)
    move.add_argument("--port", type=int, default=None)
    move.add_argument("--https", action="store_true")
    move.add_argument("--no-backup", action="store_true")

    sub.add_parser("check", help="Check enrollment and connectivity")

    args = parser.parse_args()
    if args.command == "heartbeat":
        send_heartbeat(args.config or None)
    elif args.command == "enroll":
        enroll_agent(
            args.config or None,
            args.bootstrap_key,
            args.enrollment_code,
            not args.no_backup,
            args.quiet,
        )
    elif args.command == "move":
        move_server(args.config or None, args.host, args.port, args.https, not args.no_backup)
    elif args.command == "check":
        check_agent(args.config or None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
