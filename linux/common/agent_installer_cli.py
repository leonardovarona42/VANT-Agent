#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import os
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml


BASE_DIR = Path(__file__).resolve().parents[1]
BOOTSTRAP_KEY_PATH = BASE_DIR / "common" / "bootstrap.key"
DEFAULT_AGENT_SHARED_SECRET = "VANT-SIEM-AGENT-BOOTSTRAP-2026"

_SESSION = None
def _http_session():
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.verify = False
        _SESSION.timeout = 10
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return _SESSION


def _read_yaml(path):
    if not path or not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _write_yaml(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )


def _tty_input(prompt):
    """Read input from the controlling terminal (/dev/tty) if available."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        with open("/dev/tty", "r") as tty:
            return tty.readline().strip()
    except (IOError, OSError):
        return input().strip()


def _prompt(text, default=None):
    hint = f" [{default}]" if default is not None and default != "" else ""
    prompt = f"{text}{hint}: "
    if sys.stdin.isatty():
        value = input(prompt).strip()
    else:
        value = _tty_input(prompt)
    return value if value else (default if default is not None else "")


def _prompt_int(text, default, min_value=None, max_value=None):
    while True:
        value = _prompt(text, default)
        try:
            num = int(value)
        except ValueError:
            print("  Valor invalido. Debe ser numero.")
            continue
        if min_value is not None and num < min_value:
            print(f"  Debe ser >= {min_value}.")
            continue
        if max_value is not None and num > max_value:
            print(f"  Debe ser <= {max_value}.")
            continue
        return num


def _prompt_bool(text, default=False):
    suffix = "S/n" if default else "s/N"
    prompt = f"{text} [{suffix}]: "
    if sys.stdin.isatty():
        value = input(prompt).strip().lower()
    else:
        value = _tty_input(prompt).lower()
    if not value:
        return default
    return value in ("s", "si", "y", "yes")


def _prompt_choice(text, options, default):
    options_text = "/".join(options)
    value = _prompt(f"{text} ({options_text})", default).lower()
    if value in options:
        return value
    print(f"  Opcion invalida. Usando {default}.")
    return default


def _build_enroll_url(host, port, https_enabled):
    scheme = "https" if https_enabled else "http"
    return f"{scheme}://{host}:{port}/inventory/api/agent/enroll/"


def _build_bootstrap_url(host, port, https_enabled):
    scheme = "https" if https_enabled else "http"
    return f"{scheme}://{host}:{port}/inventory/api/agent/bootstrap/"


def _load_bootstrap_key():
    env_key = os.environ.get("VANT_AGENT_BOOTSTRAP_KEY", "").strip()
    if env_key:
        return env_key
    env_shared = os.environ.get("VANT_AGENT_SHARED_SECRET", "").strip()
    if env_shared:
        return env_shared
    if BOOTSTRAP_KEY_PATH.exists():
        try:
            return BOOTSTRAP_KEY_PATH.read_text(encoding="utf-8").strip()
        except Exception:
            return ""
    return ""


def _fetch_bootstrap_secret(host, port, https_enabled, agent_id):
    url = _build_bootstrap_url(host, port, https_enabled)
    try:
        headers = {"X-Agent-Id": agent_id}
        response = _http_session().get(url, headers=headers, timeout=6)
        if "application/json" not in response.headers.get("Content-Type", ""):
            return ""
        data = response.json()
        if response.status_code == 200 and data.get("ok") and data.get("secret"):
            return data.get("secret", "")
    except Exception:
        return ""
    return ""


def _sign_request(secret, agent_id, host_name, timestamp):
    message = f"{agent_id}:{host_name}:{timestamp}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _owner_account():
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    user = sudo_user or os.environ.get("USER", "").strip() or os.environ.get("USERNAME", "").strip()
    return user


def _probe_endpoint(endpoint):
    try:
        return _http_session().get(endpoint, timeout=5).ok
    except Exception:
        return False


def _probe_control_server(host, port, https_enabled, agent_id):
    url = _build_bootstrap_url(host, port, https_enabled)
    try:
        response = _http_session().get(url, headers={"X-Agent-Id": agent_id}, timeout=6)
        return True, response.status_code
    except Exception as exc:
        return False, str(exc)


def _ensure_dict(root, *keys):
    cur = root
    for key in keys:
        cur = cur.setdefault(key, {})
    return cur


def _apply_agent_identity(cfg):
    agent_cfg = _ensure_dict(cfg, "agent")
    agent_cfg["id"] = _prompt("Agent ID", agent_cfg.get("id", socket.gethostname()))
    agent_cfg["host_name"] = _prompt("Host name", agent_cfg.get("host_name", socket.gethostname()))
    agent_cfg["interval_seconds"] = _prompt_int(
        "Intervalo (segundos)",
        agent_cfg.get("interval_seconds", 10),
        1,
        3600,
    )
    agent_cfg["log_level"] = _prompt("Log level", agent_cfg.get("log_level", "INFO"))
    agent_cfg["log_file"] = _prompt("Log file", agent_cfg.get("log_file", "/var/log/vant-siem/agent.log"))
    agent_cfg["log_max_bytes"] = _prompt_int(
        "Log max bytes",
        agent_cfg.get("log_max_bytes", 10485760),
        1024,
        1024 * 1024 * 1024,
    )
    agent_cfg["log_backup_count"] = _prompt_int(
        "Log backup count",
        agent_cfg.get("log_backup_count", 5),
        0,
        50,
    )
    agent_cfg["log_every_cycles"] = _prompt_int(
        "Log cada N ciclos",
        agent_cfg.get("log_every_cycles", 60),
        1,
        10000,
    )


def _apply_connection(cfg):
    output_cfg = _ensure_dict(cfg, "output")
    tls_cfg = _ensure_dict(output_cfg, "tls")
    control_cfg = _ensure_dict(cfg, "control")

    server_url = _prompt("VANT-SIEM Server URL", "https://192.168.12.43")
    server_url = server_url.rstrip("/")
    timeout = _prompt_int("Timeout (segundos)", output_cfg.get("timeout_seconds", 10), 1, 120)

    # All services behind the same Nginx reverse proxy
    is_https = server_url.startswith("https")
    output_cfg["endpoint"] = f"{server_url}/logs/api/ingest/bulk/"
    output_cfg["source_endpoint"] = f"{server_url}/logs/api/sources/"
    output_cfg["timeout_seconds"] = timeout
    tls_cfg["enabled"] = False
    tls_cfg["verify"] = False
    tls_cfg["ca_cert"] = ""

    control_cfg["server_url"] = server_url
    control_cfg["require_https"] = bool(is_https)
    control_cfg["verify_ssl"] = False
    control_cfg["poll_seconds"] = int(control_cfg.get("poll_seconds", 30) or 30)
    control_cfg["inventory_seconds"] = int(control_cfg.get("inventory_seconds", 86400) or 86400)
    control_cfg["dlp_poll_seconds"] = int(control_cfg.get("dlp_poll_seconds", 60) or 60)
    control_cfg["dlp_scan_seconds"] = int(control_cfg.get("dlp_scan_seconds", 30) or 30)

    # Ensure DLP and asset_audit sections exist
    _ensure_dict(cfg, "aegis_dlp")
    _ensure_dict(cfg, "asset_audit")

    parsed = urlparse(server_url)
    return {
        "server_url": server_url,
        "server_host": parsed.hostname or "",
        "server_port": str(parsed.port or (443 if is_https else 80)),
        "server_https": is_https,
    }


def _apply_auth(cfg, connection_info, agent_id, host_name):
    auth_cfg = _ensure_dict(cfg, "output", "auth")
    auth_mode = _prompt_choice("Modo auth", ["none", "basic", "token"], auth_cfg.get("mode", "none"))
    auth_cfg["mode"] = auth_mode
    enrollment_code = ""
    bootstrap_key = ""

    if auth_mode == "basic":
        auth_cfg["username"] = _prompt("Usuario", auth_cfg.get("username", ""))
        auth_cfg["password"] = _prompt("Password", auth_cfg.get("password", ""))
        auth_cfg["token"] = ""
    elif auth_mode == "token":
        auth_cfg["token"] = _prompt("Token", auth_cfg.get("token", ""))
        auth_cfg["username"] = ""
        auth_cfg["password"] = ""
    else:
        auth_cfg["username"] = ""
        auth_cfg["password"] = ""
        auth_cfg["token"] = ""
        enrollment_code = _prompt("Codigo de enrolamiento (opcional)", "")
        bootstrap_key = _prompt("Bootstrap key (opcional)", "")

    should_test = _prompt_bool("Probar conexion y enrolar", True)
    if not should_test:
        return False

    srv_host = connection_info.get("server_host") or urlparse(connection_info.get("server_url", "")).hostname or "127.0.0.1"
    srv_port = connection_info.get("server_port") or str(urlparse(connection_info.get("server_url", "")).port or "80")
    srv_https = connection_info.get("server_https", False)

    control_ok, control_info = _probe_control_server(
        srv_host, srv_port, srv_https, agent_id,
    )
    if control_ok:
        print(f"  Control server responde. Bootstrap status: {control_info}")
    else:
        print(f"  Control server no responde: {control_info}")

    if auth_mode == "none":
        shared_secret = bootstrap_key.strip() or _load_bootstrap_key()
        if not shared_secret:
            shared_secret = _fetch_bootstrap_secret(
                srv_host, srv_port, srv_https, agent_id,
            )
        if not shared_secret:
            shared_secret = DEFAULT_AGENT_SHARED_SECRET

        timestamp = str(int(time.time()))
        signature = _sign_request(shared_secret, agent_id, host_name, timestamp)
        payload = {
            "agent_id": agent_id,
            "host_name": host_name,
            "timestamp": timestamp,
            "signature": signature,
            "install_owner_account": _owner_account(),
        }
        if enrollment_code:
            payload["enrollment_code"] = enrollment_code
        enroll_url = _build_enroll_url(
            connection_info["server_host"],
            connection_info["server_port"],
            connection_info["server_https"],
        )
        try:
            response = _http_session().post(enroll_url, json=payload, timeout=8)
            data = {}
            if "application/json" in response.headers.get("Content-Type", ""):
                data = response.json()
            if response.status_code == 200 and data.get("ok") and data.get("token"):
                auth_cfg["mode"] = "token"
                auth_cfg["token"] = data.get("token", "")
                auth_cfg["username"] = ""
                auth_cfg["password"] = ""
                print("  Token obtenido correctamente.")
            else:
                print(f"  No se pudo enrolar el agente. Status: {response.status_code}")
        except Exception as exc:
            print(f"  Error al enrolar: {exc}")
    elif auth_mode == "token" and auth_cfg.get("token", "").strip():
        print("  Token configurado manualmente.")
    else:
        print("  Modo basic configurado; el enrolamiento automatico se omite.")

    endpoint = cfg.get("output", {}).get("endpoint", "")
    if _probe_endpoint(endpoint):
        print("  Endpoint OpenSearch responde.")
    else:
        print("  Endpoint OpenSearch no responde.")
    return bool(auth_cfg.get("token", "").strip())


def _apply_collectors(cfg):
    collectors = _ensure_dict(cfg, "collectors")

    suricata_cfg = _ensure_dict(collectors, "suricata")
    suricata_cfg["enabled"] = _prompt_bool("Habilitar Suricata", suricata_cfg.get("enabled", False))
    suricata_cfg["path"] = _prompt("Ruta Suricata", suricata_cfg.get("path", "/var/log/suricata/eve.json"))
    suricata_cfg["start_position"] = suricata_cfg.get("start_position", "end")
    suricata_cfg["max_lines_per_cycle"] = int(suricata_cfg.get("max_lines_per_cycle", 600))

    pg_cfg = _ensure_dict(collectors, "postgres")
    pg_cfg["enabled"] = _prompt_bool("Habilitar PostgreSQL", pg_cfg.get("enabled", False))
    pg_cfg["path"] = _prompt(
        "Ruta PostgreSQL",
        pg_cfg.get("path", "/var/log/postgresql/postgresql-16-main.log"),
    )
    pg_cfg["start_position"] = pg_cfg.get("start_position", "end")
    pg_cfg["max_lines_per_cycle"] = int(pg_cfg.get("max_lines_per_cycle", 400))

    file_cfg = _ensure_dict(collectors, "file_logs")
    file_cfg["enabled"] = _prompt_bool("Habilitar File Logs", file_cfg.get("enabled", False))
    keep_defaults = _prompt_bool("Mantener lista de file_logs actual", True)
    if not keep_defaults:
        item = {
            "enabled": True,
            "source_name": _prompt("Nombre de fuente", "file-log"),
            "path": _prompt("Ruta file log", "/var/log/syslog"),
            "event_category": _prompt("Categoria", "file.log"),
            "severity": _prompt("Severidad", "info"),
            "tags": [t.strip() for t in _prompt("Tags (comma)", "file,log").split(",") if t.strip()],
            "start_position": "end",
            "max_lines_per_cycle": 400,
        }
        file_cfg["items"] = [item]


def _show_summary(cfg):
    print("\nResumen de configuracion:")
    print(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Ruta de config.yaml")
    parser.add_argument("--template", default="", help="Ruta de template base")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--gdisable", action="store_true", help="Deshabilitar integracion grafica/tray")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    template_path = Path(args.template).resolve() if args.template else None

    if args.non_interactive:
        base = _read_yaml(config_path) or _read_yaml(template_path) or {}
        _write_yaml(config_path, base)
        print(f"Config escrito en {config_path}")
        return 0

    base = _read_yaml(config_path)
    if not base and template_path:
        base = _read_yaml(template_path)

    print("VANT-SIEM Agent Installer (Linux CLI)")
    print("Presiona Enter para mantener valores por defecto.\n")
    print(f"Modo grafico: {'deshabilitado' if args.gdisable else 'habilitado'}\n")

    _apply_agent_identity(base)
    connection_info = _apply_connection(base)
    agent_id = base.get("agent", {}).get("id", "agent-001")
    host_name = base.get("agent", {}).get("host_name", socket.gethostname())
    enrolled = _apply_auth(base, connection_info, agent_id, host_name)
    _apply_collectors(base)
    install_cfg = _ensure_dict(base, "install")
    install_cfg["graphics_disabled"] = bool(args.gdisable)
    install_cfg["last_enrollment_ok"] = bool(enrolled)
    _show_summary(base)

    if not _prompt_bool("Guardar configuracion", True):
        print("Cancelado. No se guardo config.")
        return 1

    _write_yaml(config_path, base)
    print(f"Config guardado en {config_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
