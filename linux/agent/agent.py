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

import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests

from collectors.snort import SnortCollector
from collectors.suricata import SuricataCollector
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


def build_collectors(cfg, host_ip=""):
    agent_cfg = cfg.get("agent", {})
    collectors_cfg = cfg.get("collectors", {})
    if host_ip:
        agent_cfg = {**agent_cfg, "host_ip": host_ip}
    collectors = []

    if collectors_cfg.get("snort", {}).get("enabled"):
        collectors.append(SnortCollector(collectors_cfg.get("snort"), agent_cfg))
    if collectors_cfg.get("suricata", {}).get("enabled"):
        collectors.append(SuricataCollector(collectors_cfg.get("suricata"), agent_cfg))
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
                f"{control_server}/inventory/api/command-result/",
                {"command_id": cmd_id, "status": "completed", "result": {}},
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
                    f"{control_server}/inventory/api/command-result/",
                    {"command_id": cmd_id, "status": "failed", "error": str(exc)},
                    control_token,
                    timeout=8,
                )
            except Exception:
                pass


def _detect_host():
    hostname = socket.gethostname()
    ip = ""
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = ""
    if ip.startswith("127.") or not ip:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
        except Exception:
            ip = ""
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
        log_file = "/var/log/vant-siem/agent.log"

    log_dir = Path(log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("vant-siem-agent")
    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    max_bytes = int(agent_cfg.get("log_max_bytes", 10 * 1024 * 1024))
    backup_count = int(agent_cfg.get("log_backup_count", 5))
    file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

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


def _control_post(url, payload, token, timeout=8, verify=False):
    headers = _control_headers(token)
    return requests.post(url, json=payload, headers=headers, timeout=timeout, verify=verify)


def _spawn_detached_process(args):
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
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


def _build_inventory_payload(agent_id, inventory):
    hw_list = inventory.get("hardware", []) or []
    hw = {}
    for item in hw_list:
        ct = item.get("component_type", "")
        if ct == "cpu":
            hw["cpu_model"] = item.get("name", "")
        elif ct == "board":
            hw["motherboard_model"] = item.get("model", "")
            hw["motherboard_manufacturer"] = item.get("vendor", "")
        elif ct == "bios":
            hw["bios_version"] = item.get("model", "")
            hw["serial_number"] = item.get("serial_number", "")
        elif ct == "system":
            hw["manufacturer"] = item.get("vendor", "")
            hw["product_name"] = item.get("name", "")
        elif ct == "memory":
            name = item.get("name", "")
            import re
            m = re.search(r'(\d+(?:\.\d+)?)\s*GB?', name, re.IGNORECASE)
            if m:
                hw["ram_total_gb"] = float(m.group(1))
            else:
                m2 = re.search(r'(\d+(?:\.\d+)?)\s*MB', name, re.IGNORECASE)
                if m2:
                    hw["ram_total_gb"] = float(m2.group(1)) / 1024.0
        elif ct == "disk":
            hw.setdefault("disks", []).append(item)
        elif ct == "network":
            hw.setdefault("network_interfaces", []).append(item)
    return {
        "agent_id": agent_id,
        "hardware": hw,
        "software": inventory.get("software", []) or [],
    }


def _current_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception:
        pass
    return [ip for ip in ips if ip and not ip.startswith("127.")]


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
    collectors = build_collectors(cfg, host_ip)
    interval = int(agent_cfg.get("interval_seconds", 10))
    log_every = int(agent_cfg.get("log_every_cycles", 60))
    control_cfg = _control_config(cfg)
    control_server = (control_cfg.get("server_url") or "").rstrip("/")
    control_poll = int(control_cfg.get("poll_seconds", 30))
    control_token = (
        cfg.get("output", {}).get("auth", {}).get("token")
        or control_cfg.get("token", "")
    )
    inventory_enabled = bool((cfg.get("asset_audit", {}) or {}).get("enabled", True))
    dlp_enabled = bool((cfg.get("aegis_dlp", {}) or {}).get("enabled", True))
    inventory_service = AuditInventoryService(config_path) if inventory_enabled else None
    dlp_service = AegisDlpService(config_path, cfg) if dlp_enabled else None
    inventory_seconds = int(control_cfg.get("inventory_seconds", 86400))
    dlp_poll_seconds = int(control_cfg.get("dlp_poll_seconds", max(30, min(inventory_seconds, 120))))
    dlp_scan_seconds = int(control_cfg.get("dlp_scan_seconds", max(30, min(inventory_seconds, 60))))
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

    logger.info("agent.config control_server=%s inventory=%s dlp=%s",
        control_server, inventory_enabled, dlp_enabled)

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

    agent_id = agent_cfg.get("id", "agent")
    screen_service = None
    try:
        from services.screen import ScreenCaptureService
        screen_service = ScreenCaptureService(out, control_server, control_token, agent_id, logger)
        logger.info("screen.service initialized")
    except Exception as e:
        logger.warning("screen.service init error=%s", e)

    if control_server:
        try:
            hb_payload = {
                "agent_id": agent_id,
                "host_name": agent_cfg.get("host_name", ""),
                "host_ip": agent_cfg.get("host_ip", ""),
                "ip_address": agent_cfg.get("host_ip", ""),
                "agent_version": AGENT_VERSION,
                "ips": _current_ips(),
            }
            resp = _control_post(
                f"{control_server}/inventory/api/heartbeat/",
                hb_payload,
                control_token,
                timeout=8,
            )
        if resp and resp.status_code == 200:
            data = resp.json()
            cmd_resp = _control_post(
                f"{control_server}/inventory/api/agent/commands/pull/",
                {"agent_id": agent_id},
                control_token,
                timeout=8,
            )
            if cmd_resp and cmd_resp.status_code == 200:
                cmd_data = cmd_resp.json()
                commands = cmd_data.get("commands", [])
                if commands:
                    logger.info("startup.commands count=%s", len(commands))
                for cmd_item in commands:
                    cmd_type = cmd_item.get("command_type", "")
                    cmd_id = cmd_item.get("command_id", "")
                    cmd_payload = cmd_item.get("payload", {})
                    if cmd_type == "stop":
                        logger.warning("command.stop at startup")
                        if screen_service:
                            screen_service.stop()
                        logger.info("agent.stopped")
                        return "stop"
                    elif cmd_type == "restart":
                        logger.warning("command.restart at startup")
                        if screen_service:
                            screen_service.stop()
                        logger.info("agent.stopped")
                        return "restart"
                    elif cmd_type == "push_config":
                        logger.info("command.push_config at startup")
                        _apply_push_config(config_path, cmd_payload, logger, control_server, control_token, cmd_id)
                        cfg = load_cfg(config_path)
                        agent_cfg = cfg.get("agent", {})
                        collectors = build_collectors(cfg, host_ip)
                        interval = int(agent_cfg.get("interval_seconds", 10))
                    elif cmd_type == "activate":
                        logger.info("command.activate at startup")
                        if cmd_id:
                            _control_post(
                                f"{control_server}/inventory/api/command-result/",
                                {"command_id": cmd_id, "status": "completed", "result": {}},
                                control_token,
                                timeout=8,
                            )
    except Exception as e:
        logger.warning("startup.commands check error=%s", e)

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
                logger.error("send_events failed error=%s batch=%s", exc, len(batch))
            now = time.time()
            if control_server and now >= next_control:
                try:
                    payload = {
                        "agent_id": agent_cfg.get("id", "agent"),
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "ip_address": agent_cfg.get("host_ip", ""),
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
                                if screen_service:
                                    screen_service.stop()
                                return "stop"
                            elif cmd_type == "restart":
                                logger.warning("command.restart received")
                                if cmd_id:
                                    _control_post(
                                        f"{control_server}/inventory/api/command-result/",
                                        {"command_id": cmd_id, "status": "completed", "result": {}},
                                        control_token,
                                        timeout=8,
                                    )
                                if screen_service:
                                    screen_service.stop()
                                return "restart"
                            elif cmd_type == "push_config":
                                logger.info("command.push_config received")
                                _apply_push_config(config_path, cmd_payload, logger, control_server, control_token, cmd_id)
                                cfg = load_cfg(config_path)
                                agent_cfg = cfg.get("agent", {})
                                collectors = build_collectors(cfg, host_ip)
                                interval = int(agent_cfg.get("interval_seconds", 10))
                                control_cfg = _control_config(cfg)
                                control_poll = int(control_cfg.get("poll_seconds", 30))
                            elif cmd_type == "start_screen_share":
                                logger.info("command.start_screen_share received")
                                if screen_service:
                                    screen_service.start()
                                    if cmd_id:
                                        _control_post(
                                            f"{control_server}/inventory/api/command-result/",
                                            {"command_id": cmd_id, "status": "completed", "result": {"status": "screen_sharing_started"}},
                                            control_token,
                                            timeout=8,
                                        )
                                else:
                                    if cmd_id:
                                        _control_post(
                                            f"{control_server}/inventory/api/command-result/",
                                            {"command_id": cmd_id, "status": "failed", "error": "screen_service_unavailable"},
                                            control_token,
                                            timeout=8,
                                        )
                            elif cmd_type == "stop_screen_share":
                                logger.info("command.stop_screen_share received")
                                if screen_service:
                                    screen_service.stop()
                                    if cmd_id:
                                        _control_post(
                                            f"{control_server}/inventory/api/command-result/",
                                            {"command_id": cmd_id, "status": "completed", "result": {"status": "screen_sharing_stopped"}},
                                            control_token,
                                            timeout=8,
                                        )
                            elif cmd_type == "activate":
                                logger.info("command.activate received")
                                if cmd_id:
                                    _control_post(
                                        f"{control_server}/inventory/api/command-result/",
                                        {"command_id": cmd_id, "status": "completed", "result": {}},
                                        control_token,
                                        timeout=8,
                                    )
                except Exception as exc:
                    logger.warning("control poll failed error=%s", exc)
                next_control = now + control_poll

            if control_server and inventory_service and now >= next_inventory:
                try:
                    inv = inventory_service.collect()
                    _control_post(
                        f"{control_server}/inventory/api/inventory/submit/",
                        _build_inventory_payload(agent_cfg.get("id", "agent"), inv),
                        control_token,
                        timeout=30,
                    )
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
                            resp = dlp_service.submit_threats(
                                control_server, control_token,
                                agent_cfg.get("id", "agent"), pending,
                            )
                            if resp is not None and resp.status_code in (200, 201):
                                dlp_service.clear_pending_incidents()
                                logger.info("dlp incidents uploaded count=%s", len(pending))
                            else:
                                logger.warning("dlp incident upload failed status=%s", resp.status_code if resp is not None else "no response")
                except Exception as exc:
                    logger.warning("dlp incident upload failed error=%s", exc)
                next_dlp_scan = now + dlp_scan_seconds

            _sleep_with_stop(stop_event, interval)
        except Exception as exc:
            logger.exception("agent.loop crashed error=%s", exc)
            _sleep_with_stop(stop_event, 5)

    if screen_service:
        screen_service.stop()
    logger.info("agent.stopped")


def run(config_path):
    import threading
    while True:
        stop_ev = threading.Event()
        reason = run_with_stop(config_path, stop_ev)
        if stop_ev.is_set() or reason != "restart":
            break


def default_config_path():
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent / "config.yaml")
    return "/etc/vant-siem/config.yaml"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=default_config_path())
    args = parser.parse_args()
    run(args.config)
