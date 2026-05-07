import os
import sys
from pathlib import Path

import yaml

DEFAULTS = {
    "server": {
        "url": "http://localhost:8000",
        "logs_url": "http://localhost:9201",
        "auth_mode": "none",
        "auth_token": "",
        "auth_username": "",
        "auth_password": "",
    },
    "agent": {
        "host_name": "",
        "check_interval": 60,
        "max_batch_size": 500,
        "heartbeat_interval": 300,
        "log_level": "INFO",
        "log_file": "",
    },
    "collectors": {
        "snort": {"enabled": False, "path": ""},
        "suricata": {"enabled": False, "path": ""},
        "windows_eventlog": {"enabled": False, "channels": ["Security", "System"]},
        "postgres": {"enabled": False, "path": ""},
        "file_logs": {"enabled": False, "items": []},
    },
    "inventory": {
        "enabled": True,
        "interval": 86400,
    },
    "dlp": {
        "enabled": False,
        "scan_paths": [],
        "scan_extensions": [".docx", ".xlsx", ".pdf", ".txt"],
        "keywords": ["clasificado", "secreto", "restringido"],
    },
    "logging": {
        "level": "INFO",
        "file": "vant-agent.log",
        "max_bytes": 10485760,
        "backup_count": 5,
    },
}


def load_config(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return _deep_merge(DEFAULTS, raw)


def _deep_merge(base, override):
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def find_config():
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        cfg = exe_dir / "config.yaml"
        if cfg.exists():
            return str(cfg)
        cfg = exe_dir / "config.example.yaml"
        if cfg.exists():
            return str(cfg)
    local = Path("config.yaml")
    if local.exists():
        return str(local)
    return None


def get_log_dir(config_path, log_file):
    if log_file and os.path.isabs(log_file):
        return Path(log_file).parent
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    base = Path(config_path).resolve().parent
    return base


def save_config(config_path, cfg):
    p = Path(config_path)
    existing = yaml.safe_load(p.read_text(encoding="utf-8")) or {} if p.exists() else {}
    merged = _deep_merge(existing, cfg)
    p.write_text(yaml.dump(merged, default_flow_style=False, sort_keys=False, allow_unicode=True), encoding="utf-8")
