import os
import sys
from pathlib import Path

import yaml

def find_config():
    """Find configuration file in standard locations"""
    # Check current directory
    if os.path.exists("config.yaml"):
        return "config.yaml"

    # Check user home directory
    home_config = os.path.expanduser("~/config.yaml")
    if os.path.exists(home_config):
        return home_config

    # Check /etc directory
    etc_config = "/etc/vant/config.yaml"
    if os.path.exists(etc_config):
        return etc_config

    # Return default location (will be created if doesn't exist)
    return "config.yaml"

def load_config(config_path):
    """Load configuration from YAML file, merging with defaults"""
    config = DEFAULTS.copy()

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    # Deep merge user config with defaults
                    config = _deep_merge(config, user_config)
        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
            print("Using default configuration")
    else:
        print(f"Info: Config file {config_path} not found, using defaults")

    return config

def _deep_merge(base, update):
    """Deep merge two dictionaries"""
    for key, value in update.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base

DEFAULTS = {
    "server": {
        "url": "https://192.168.12.43",
        "auth_mode": "none",
        "auth_token": "",
        "service_secret": "",
        "tls": {
            "verify": True,
            "ca_cert": "",
            "client_cert": "",
            "client_key": "",
        },
    },
    "agent": {
        "host_name": "",
        "check_interval": 60,
        "heartbeat_interval": 300,
        "log_level": "INFO",
        "log_file": "",
    },
    "collectors": {
        "snort": {"enabled": False, "path": ""},
        "suricata": {"enabled": False, "path": ""},
        "windows_eventlog": {"enabled": False, "channels": ["Security", "System"]},
        "syslog": {"enabled": False, "path": "/var/log/syslog"},
        "journald": {"enabled": False},
        "postgres": {"enabled": False, "path": ""},
        "file_logs": {"enabled": False, "items": []},
    },
    "inventory": {
        "enabled": True,
        "interval": 300,
    },
    "dlp": {
        "enabled": True,
        "scan_paths": [],
        "scan_extensions": [".docx", ".x", ".xlsx", ".pdf", ".txt"],
        "keywords": ["clasificado", "secreto", "restringido"],
        "scan_interval": 30,
        "realtime_enabled": True,
    },
    "monitoring": {
        "enabled": False,
        "services": {
            "enabled": False,
            "monitored_services": [],
            "check_apt_updates": True,
            "apt_check_interval": 86400,
        },
    },
    "logging": {
        "level": "INFO",
        "file": "vant-agent.log",
        "max_bytes": 10485760,
        "backup_count": 5,
    },
    "rules": {
        "directory": "rules",
        "reload_interval": 300,
    },
    "cti": {
        "enabled": True,
        "update_interval": 3600,
        "data_dir": "./cti_data",
        "alienvault_otx": {
            "enabled": True,
            "update_interval": 3600
        },
        "abuse_ch": {
            "sslbl": {
                "enabled": True,
                "update_interval": 7200
            },
            "feodotracker": {
                "enabled": True,
                "update_interval": 3600
            }
        }
    },
}