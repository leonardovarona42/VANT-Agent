import argparse
import logging
import socket
import sys
import time
import os
import threading
import json
import subprocess
import platform
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from collections import defaultdict

import yaml
import requests

from collectors.snort import SnortCollector
from collectors.suricata import SuricataCollector
try:
    from collectors.windows_eventlog import WindowsEventLogCollector
except ImportError:
    WindowsEventLogCollector = None
from collectors.postgres_log import PostgresLogCollector
from collectors.file_log import FileLogCollector
from output import OutputClient
from services.audit_inventory import AuditInventoryService
from services.aegis_dlp import AegisDlpService

AGENT_VERSION = "v1.01"


def load_cfg(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def build_collectors(cfg):
    agent_cfg = cfg.get("agent", {})
    collectors_cfg = cfg.get("collectors", {})
    collectors = []

    if collectors_cfg.get("snort", {}).get("enabled"):
        collectors.append(SnortCollector(collectors_cfg.get("snort"), agent_cfg))
    if collectors_cfg.get("suricata", {}).get("enabled"):
        collectors.append(SuricataCollector(collectors_cfg.get("suricata"), agent_cfg))
    if WindowsEventLogCollector is not None and collectors_cfg.get("windows_eventlog", {}).get("enabled"):
        winlog_cfg = collectors_cfg.get("windows_eventlog") or {}
        channels = winlog_cfg.get("channels") or []
        if isinstance(channels, str):
            channels = [item.strip() for item in channels.split(",") if item.strip()]
        if channels:
            for channel in channels:
                per_channel_cfg = dict(winlog_cfg)
                per_channel_cfg["channel"] = channel
                collectors.append(WindowsEventLogCollector(per_channel_cfg, agent_cfg))
        else:
            collectors.append(WindowsEventLogCollector(winlog_cfg, agent_cfg))
    if collectors_cfg.get("postgres", {}).get("enabled"):
        collectors.append(PostgresLogCollector(collectors_cfg.get("postgres"), agent_cfg))
    if collectors_cfg.get("file_logs", {}).get("enabled"):
        collectors.append(FileLogCollector(collectors_cfg.get("file_logs"), agent_cfg))

    return collectors


def _apply_push_config(config_path, payload, logger, control_server, control_token, cmd_id):
    try:
        cfg = load_cfg(config_path)

        new_config = payload.get("config", {})

        if "inventory" in new_config:
            inv_cfg = new_config["inventory"]
            control = cfg.get("control", {})
            control["inventory_seconds"] = inv_cfg.get("interval", control.get("inventory_seconds", 86400))
            cfg["control"] = control

        if "collectors" in new_config:
            cfg["collectors"] = new_config["collectors"]

        if "dlp" in new_config:
            dlp_cfg = cfg.get("aegis_dlp", {})
            dlp_cfg.update(new_config["dlp"])
            cfg["aegis_dlp"] = dlp_cfg

        config_text = yaml.dump(cfg, default_flow_style=False, sort_keys=False, allow_unicode=True)
        Path(config_path).write_text(config_text, encoding="utf-8")
        logger.info("config.applied path=%s", config_path)

        if cmd_id:
            _control_post(
                f"{control_server}/inventory/api/agent/commands/ack/",
                {"command_id": cmd_id, "status": "done"},
                control_token,
                timeout=8,
            )

        if _restart_self(config_path, logger):
            logger.warning("config.applied restarted to apply collector changes")
            sys.exit(0)
        else:
            logger.error("config.applied restart failed")
    except Exception as exc:
        logger.exception("config.apply failed error=%s", exc)
        if cmd_id:
            try:
                _control_post(
                    f"{control_server}/inventory/api/agent/commands/ack/",
                    {"command_id": cmd_id, "status": "error: " + str(exc)},
                    control_token,
                    timeout=8,
                )
            except Exception:
                pass


def _get_local_ips():
    ips = set()
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    try:
        import subprocess
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
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.connect(("8.8.8.8", 80))
                ips.add(s.getsockname()[0])
        except Exception:
            pass
    return [ip for ip in ips if ip and not ip.startswith("127.")]


def _detect_host():
    hostname = socket.gethostname()
    ips = _get_local_ips()
    ip = ips[0] if ips else ""
    return hostname, ip


def _ensure_host_fields(event, host_name, host_ip):
    if not event.get("host_name"):
        event["host_name"] = host_name
    raw = event.get("raw_payload")
    if raw is None or not isinstance(raw, dict):
        raw = {}
    if host_name and "host_name" not in raw:
        raw["host_name"] = host_name
    if host_ip and "host_ip" not in raw:
        raw["host_ip"] = host_ip
    event["raw_payload"] = raw
    return event


def _configure_logging(agent_cfg):
    level_name = str(agent_cfg.get("log_level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    log_file = agent_cfg.get("log_file")
    if not log_file:
        # Default to /var/log on Linux, executable dir otherwise.
        if sys.platform.startswith("linux"):
            log_file = "/var/log/vant-siem/agent.log"
        else:
            log_file = str(Path(sys.executable).resolve().parent / "agent.log")

    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("vant-siem-agent")
    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler with rotation
    max_bytes = int(agent_cfg.get("log_max_bytes", 10 * 1024 * 1024))
    backup_count = int(agent_cfg.get("log_backup_count", 5))
    file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    # Also log to stdout for systemd/journald
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(level)
    logger.addHandler(stream_handler)

    return logger


def _sleep_with_stop(stop_event, seconds):
    remaining = max(0, int(seconds))
    while remaining > 0:
        if stop_event.is_set():
            return
        time.sleep(1)
        remaining -= 1


def _control_config(cfg):
    return cfg.get("control", {}) or {}


def _control_headers(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


def _control_post(url, payload, token, timeout=8):
    headers = _control_headers(token)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    resp = requests.post(url, json=payload, headers=headers, timeout=timeout, verify=False)
    if not resp.ok:
        logging.getLogger("vant-siem-agent").warning(
            "control_post HTTP %s %s body=%s", resp.status_code, url, resp.text[:500]
        )
    return resp


def _extract_server_hardware(inv):
    hw_list = inv.get("hardware", [])
    result = {
        "cpu_model": "", "cpu_cores": 0, "cpu_threads": 0, "cpu_speed_ghz": 0,
        "ram_total_gb": 0, "ram_slots_used": 0, "ram_slots_total": 0,
        "motherboard_model": "", "motherboard_manufacturer": "",
        "bios_version": "", "gpu_models": [], "disks": [],
        "network_interfaces": [], "serial_number": "",
        "manufacturer": "", "product_name": "",
    }
    for item in hw_list:
        ct = item.get("component_type", "")
        if ct == "bios":
            result["bios_version"] = item.get("model", "")
            if not result["serial_number"]:
                result["serial_number"] = item.get("serial_number", "")
        elif ct == "system":
            result["manufacturer"] = item.get("vendor", "")
            result["product_name"] = item.get("name", "")
            if not result["serial_number"]:
                result["serial_number"] = item.get("serial_number", "")
        elif ct == "cpu":
            result["cpu_model"] = item.get("name", "")
        elif ct == "board":
            result["motherboard_model"] = item.get("model", "")
            result["motherboard_manufacturer"] = item.get("vendor", "")
        elif ct == "disk":
            meta = item.get("metadata", {})
            result["disks"].append({
                "model": item.get("model", ""),
                "size": meta.get("size", ""),
                "interface": meta.get("interface", ""),
                "serial": item.get("serial_number", ""),
            })
        elif ct == "network":
            result["network_interfaces"].append({
                "name": item.get("name", ""),
                "mac": item.get("serial_number", ""),
                "model": item.get("model", ""),
            })
    return result


def _spawn_detached_process(args):
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform.startswith("win"):
        creationflags = 0
        creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs["creationflags"] = creationflags
    try:
        return subprocess.Popen(args, **kwargs)
    except Exception:
        return None


def _restart_self(config_path, logger=None):
    exe = str(Path(sys.executable).resolve())
    cfg_path = Path(config_path)
    try:
        cfg_path = cfg_path.resolve()
    except Exception:
        pass
    child_args = [exe, "--config", str(cfg_path)]
    child = _spawn_detached_process(child_args)
    if child is None:
        if logger:
            logger.error("restart.spawn_failed path=%s", exe)
        return False
    if logger:
        logger.warning("restart.spawned pid=%s path=%s", child.pid, exe)
    return True


def _current_ips():
    return _get_local_ips()


def _run_powershell(cmd_args, timeout=15):
    if not sys.platform.startswith("win"):
        return None
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return subprocess.run(
            ["powershell", "-NoProfile", "-Command"] + cmd_args,
            capture_output=True, text=True, timeout=timeout, check=False,
            startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except FileNotFoundError:
        return None


def _collect_processes_windows():
    ps_script = """
    $ps = Get-Process | Where-Object { $_.Id -gt 0 } | Select-Object Id, ProcessName,
        @{N='cpu_percent';E={[math]::Round((Get-Process -Id $_.Id).CPU, 1)}},
        @{N='memory_mb';E={[math]::Round($_.WorkingSet64 / 1MB, 1)}},
        @{N='session_id';E={$_.SessionId}}
    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalPort, RemotePort, RemoteAddress, OwningProcess, State,
        @{N='protocol';E={'tcp'}}
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalPort, @{N='RemotePort';E={''}}, @{N='RemoteAddress';E={''}}, OwningProcess,
        @{N='State';E={'Listen'}},
        @{N='protocol';E={'udp'}}
    $conns = $tcp + $udp
    $result = @{ processes=($ps | ConvertTo-Json -Depth 3); connections=($conns | ConvertTo-Json -Depth 3) }
    Write-Output ($result | ConvertTo-Json -Compress)
    """
    result = _run_powershell([ps_script], timeout=20)
    if result is None or result.returncode != 0 or not result.stdout.strip():
        return [], []
    try:
        data = json.loads(result.stdout.strip())
        processes = json.loads(data.get("processes", "[]")) if isinstance(data.get("processes"), str) else data.get("processes", [])
        connections = json.loads(data.get("connections", "[]")) if isinstance(data.get("connections"), str) else data.get("connections", [])
        normalized_procs = []
        for p in processes:
            normalized_procs.append({
                "pid": p.get("Id", 0),
                "name": p.get("ProcessName", "Unknown"),
                "process_name": p.get("ProcessName", "Unknown"),
                "cpu_percent": p.get("cpu_percent", 0),
                "memory_mb": p.get("memory_mb", 0),
                "session_id": p.get("session_id", 0),
            })
        normalized_conns = []
        for c in connections:
            normalized_conns.append({
                "local_port": c.get("LocalPort", ""),
                "remote_port": c.get("RemotePort", ""),
                "remote_address": c.get("RemoteAddress", ""),
                "owning_pid": c.get("OwningProcess", 0),
                "state": c.get("State", ""),
                "protocol": c.get("protocol", "tcp"),
            })
        return normalized_procs, normalized_conns
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        logging.getLogger("vant-siem-agent").warning("collect_processes parse error=%s", exc)
        return [], []


def _collect_processes_linux():
    try:
        procs = []
        result = subprocess.run(
            ["ps", "aux", "--sort=-%cpu"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            for line in lines[1:]:
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue
                try:
                    procs.append({
                        "pid": int(parts[1]),
                        "name": parts[10][:100],
                        "process_name": parts[10][:100],
                        "cpu_percent": float(parts[2]),
                        "memory_mb": round(float(parts[3]) * 1024 / 1024, 1),
                        "session_id": parts[5] if len(parts) > 5 else "",
                    })
                except (ValueError, IndexError):
                    continue

        conns = []
        result2 = subprocess.run(
            ["ss", "-tan"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result2.returncode == 0:
            for line in result2.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue
                local = parts[3]
                peer = parts[4]
                local_port = local.rsplit(":", 1)[-1] if ":" in local else ""
                remote = peer.rsplit(":", 1)
                conns.append({
                    "local_port": local_port,
                    "remote_port": remote[-1] if len(remote) > 1 else "",
                    "remote_address": remote[0] if len(remote) > 1 else peer,
                    "owning_pid": 0,
                    "state": parts[0],
                    "protocol": "tcp",
                })
        return procs, conns
    except Exception:
        return [], []


def _collect_processes():
    if sys.platform.startswith("win"):
        return _collect_processes_windows()
    return _collect_processes_linux()


def run_with_stop(config_path, stop_event):
    cfg = load_cfg(config_path)
    agent_cfg = cfg.get("agent", {})
    logger = _configure_logging(agent_cfg)
    host_name, host_ip = _detect_host()
    placeholder_hosts = {
        "debian-host",
        "ubuntu-host",
        "windows-host-01",
        "windows-server-ad",
        "windows11-ids",
        "zentyal-ad",
    }
    configured_host = (agent_cfg.get("host_name") or "").strip()
    if (not configured_host) or (configured_host.lower() in placeholder_hosts):
        agent_cfg["host_name"] = host_name
    if host_ip and not agent_cfg.get("host_ip"):
        agent_cfg["host_ip"] = host_ip
    out = OutputClient(cfg.get("output", {}))
    collectors = build_collectors(cfg)
    interval = int(agent_cfg.get("interval_seconds", 10))
    log_every = int(agent_cfg.get("log_every_cycles", 60))
    control_cfg = _control_config(cfg)
    control_server = (control_cfg.get("server_url") or "").rstrip("/")
    control_poll = int(control_cfg.get("poll_seconds", 30))
    logger.info("debug control_server=%s control_poll=%s", control_server, control_poll)
    control_token = (
        cfg.get("output", {}).get("auth", {}).get("token")
        or control_cfg.get("token", "")
    )
    inventory_enabled = bool((cfg.get("asset_audit", {}) or {}).get("enabled", True))
    dlp_enabled = bool((cfg.get("aegis_dlp", {}) or {}).get("enabled", True))
    inventory_service = AuditInventoryService(config_path) if inventory_enabled else None
    dlp_service = AegisDlpService(config_path, cfg) if dlp_enabled else None
    inventory_seconds = max(30, min(int(control_cfg.get("inventory_seconds", 86400)), 86400 * 7))
    dlp_poll_seconds = max(10, min(int(control_cfg.get("dlp_poll_seconds", 60)), 3600))
    dlp_scan_seconds = max(5, min(int(control_cfg.get("dlp_scan_seconds", 30)), 3600))
    next_control = time.time() + control_poll
    next_inventory = time.time()
    next_dlp_poll = time.time()
    next_dlp_scan = time.time()
    cycle = 0

    logger.info(
        "agent.starting version=%s host=%s ip=%s interval=%ss collectors=%s",
        AGENT_VERSION,
        agent_cfg.get("host_name", ""),
        agent_cfg.get("host_ip", ""),
        interval,
        ",".join([c.source_type for c in collectors]) or "none",
    )

    # register/upsert enabled sources
    for c in collectors:
        try:
            out.upsert_source(
                {
                    "source_id": f"{agent_cfg.get('id','agent')}-{c.source_type}",
                    "source_type": c.source_type,
                    "host_name": agent_cfg.get("host_name", ""),
                    "enabled": True,
                    "meta": {
                        **(c.cfg or {}),
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "agent_version": AGENT_VERSION,
                    },
                }
            )
        except Exception as exc:
            logger.warning("upsert_source failed source=%s error=%s", c.source_type, exc)

    while not stop_event.is_set():
        try:
            cycle += 1
            batch = []
            for collector in collectors:
                try:
                    events = collector.collect()
                    for ev in events:
                        _ensure_host_fields(ev, agent_cfg.get("host_name", ""), agent_cfg.get("host_ip", ""))
                    batch.extend(events)
                except Exception as exc:
                    logger.exception("collector failed source=%s", collector.source_type)
                    batch.append(
                        _ensure_host_fields(
                            {
                            "source_type": "agent",
                            "source_name": "agent-runtime",
                            "host_name": agent_cfg.get("host_name", ""),
                            "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "severity": "error",
                            "event_category": "agent.error",
                            "message": f"collector {collector.source_type} failed: {exc}",
                            "raw_payload": {},
                            "tags": ["agent", "error"],
                            },
                            agent_cfg.get("host_name", ""),
                            agent_cfg.get("host_ip", ""),
                        )
                    )
            try:
                out.send_events(batch)
                if log_every > 0 and (cycle % log_every == 0):
                    logger.info("cycle ok events=%s collectors=%s", len(batch), len(collectors))
            except Exception as exc:
                # Keep agent running even if output endpoint is down.
                logger.error("send_events failed error=%s batch=%s", exc, len(batch))
            now = time.time()
            logger.info("debug now=%s next_control=%s next_inventory=%s", now, next_control, next_inventory)
            if control_server and now >= next_control:
                logger.info("debug control_poll entering")
                try:
                    payload = {
                        "agent_id": agent_cfg.get("id", "agent"),
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "agent_version": AGENT_VERSION,
                        "ips": _current_ips(),
                    }
                    _control_post(
                        f"{control_server}/inventory/api/heartbeat/",
                        payload,
                        control_token,
                        timeout=8,
                    )
                    cmd_resp = _control_post(
                        f"{control_server}/inventory/api/agent/commands/pull/",
                        {"agent_id": agent_cfg.get("id", "agent")},
                        control_token,
                        timeout=8,
                    )
                    if cmd_resp.status_code == 200:
                        data = cmd_resp.json()
                        commands = data.get("commands", [])
                        if commands:
                            logger.info("pull_commands got %d commands", len(commands))
                        for cmd_item in commands:
                            cmd_type = cmd_item.get("command_type", "")
                            cmd_id = cmd_item.get("command_id", "")
                            cmd_payload = cmd_item.get("payload", {})
                            if cmd_type == "stop":
                                logger.warning("command.stop received")
                                stop_event.set()
                            elif cmd_type == "restart":
                                logger.warning("command.restart received")
                                if _restart_self(config_path, logger):
                                    if cmd_id:
                                        _control_post(
                                            f"{control_server}/inventory/api/agent/commands/ack/",
                                            {"command_id": cmd_id, "status": "done"},
                                            control_token,
                                            timeout=8,
                                        )
                                    stop_event.set()
                                    return
                                logger.error("command.restart failed to relaunch self")
                            elif cmd_type == "push_config":
                                logger.info("command.push_config received")
                                _apply_push_config(config_path, cmd_payload, logger, control_server, control_token, cmd_id)
                            elif cmd_type == "activate":
                                logger.info("command.activate received")
                                if cmd_id:
                                    _control_post(
                                        f"{control_server}/inventory/api/agent/commands/ack/",
                                        {"command_id": cmd_id, "status": "done"},
                                        control_token,
                                        timeout=8,
                                    )
                            elif cmd_type == "collect_processes":
                                logger.info("command.collect_processes received")
                                try:
                                    procs, conns = _collect_processes()
                                    _control_post(
                                        f"{control_server}/inventory/api/agent/processes/upload/",
                                        {
                                            "agent_id": agent_cfg.get("id", "agent"),
                                            "processes": procs,
                                            "connections": conns,
                                        },
                                        control_token,
                                        timeout=30,
                                    )
                                    logger.info("collect_processes uploaded procs=%d conns=%d", len(procs), len(conns))
                                except Exception as exc:
                                    logger.exception("collect_processes failed error=%s", exc)
                                if cmd_id:
                                    _control_post(
                                        f"{control_server}/inventory/api/agent/commands/ack/",
                                        {"command_id": cmd_id, "status": "done"},
                                        control_token,
                                        timeout=8,
                                    )
                    next_control = now + control_poll
                except Exception as exc:
                    logger.warning("control poll failed error=%s", exc)

            if control_server and inventory_service and now >= next_inventory:
                logger.info("debug inventory entering")
                try:
                    inv = inventory_service.collect()
                    hw = _extract_server_hardware(inv)
                    sw = inv.get("software", [])
                    _control_post(
                        f"{control_server}/inventory/api/inventory/submit/",
                        {
                            "agent_id": agent_cfg.get("id", "agent"),
                            "hardware": hw,
                            "software": sw,
                        },
                        control_token,
                        timeout=30,
                    )
                    logger.info("inventory uploaded hw=%s sw=%d", inv.get("os", ""), len(sw))
                except Exception as exc:
                    logger.warning("inventory upload failed error=%s", exc)
                next_inventory = now + inventory_seconds

            if control_server and dlp_service and now >= next_dlp_poll:
                try:
                    dlp_service.fetch_remote_config(
                        control_server,
                        control_token,
                        agent_cfg.get("id", "agent"),
                    )
                except Exception as exc:
                    logger.warning("dlp config poll failed error=%s", exc)
                next_dlp_poll = now + dlp_poll_seconds

            if dlp_service and now >= next_dlp_scan:
                try:
                    incidents = dlp_service.scan()
                    if incidents:
                        logger.info("dlp incidents detected count=%s", len(incidents))
                    if control_server:
                        pending = dlp_service.peek_pending_incidents()
                        if pending:
                            _control_post(
                                f"{control_server}/inventory/api/agent/dlp/incidents/",
                                {"agent_id": agent_cfg.get("id", "agent"), "incidents": pending},
                                control_token,
                                timeout=30,
                            )
                            dlp_service.clear_pending_incidents()
                            logger.info("dlp incidents uploaded count=%s", len(pending))
                except Exception as exc:
                    logger.warning("dlp incident upload failed error=%s", exc)
                next_dlp_scan = now + dlp_scan_seconds

            _sleep_with_stop(stop_event, interval)
        except Exception as exc:
            logger.exception("agent.loop crashed error=%s", exc)
            _sleep_with_stop(stop_event, 5)


def run(config_path):
    stop_event = threading.Event()
    run_with_stop(config_path, stop_event)


def default_config_path():
    # If running as bundled .exe, use config.yaml in executable directory.
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent / "config.yaml")
    return "opensearch_agents/config.yaml"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=default_config_path())
    args = parser.parse_args()
    run(args.config)
