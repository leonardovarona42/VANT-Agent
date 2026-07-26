from pathlib import Path

import pytest
import yaml


# ---------------------------------------------------------------------------
# Fixtures: config
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_config_dict():
    return {
        "server": {
            "url": "http://localhost:8000",
            "logs_url": "http://localhost:9201",
            "auth_mode": "none",
            "auth_token": "",
            "auth_username": "",
            "auth_password": "",
            "timeout": 15,
        },
        "agent": {
            "host_name": "test-pc",
            "host_ip": "192.168.1.10",
            "check_interval": 60,
            "id": "agent-001",
            "heartbeat_interval": 300,
        },
        "collectors": {
            "snort": {"enabled": False, "path": ""},
            "suricata": {"enabled": False, "path": ""},
            "windows_eventlog": {"enabled": False, "channels": ["Security"]},
            "file_logs": {"enabled": False, "items": []},
        },
        "inventory": {
            "enabled": True,
            "interval": 300,
        },
        "dlp": {
            "enabled": False,
            "scan_paths": [],
        },
        "logging": {
            "level": "DEBUG",
            "file": "",
            "max_bytes": 10485760,
            "backup_count": 5,
        },
    }


@pytest.fixture
def sample_config_path(tmp_path, sample_config_dict):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump(sample_config_dict, default_flow_style=False), encoding="utf-8")
    return str(p)


@pytest.fixture
def mock_stop_event():
    class _MockStop:
        def __init__(self):
            self._stopped = False

        def is_set(self):
            return self._stopped

        def set(self):
            self._stopped = True

    return _MockStop()


# ---------------------------------------------------------------------------
# Fixtures: HTTP mocking helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_response():
    """Simple helper to build a requests.Response-like object."""
    class MockResp:
        def __init__(self, status_code=200, json_data=None, text=""):
            self.status_code = status_code
            self._json = json_data or {}
            self.text = text

        def json(self):
            return self._json

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP {self.status_code}")

    return MockResp


# ---------------------------------------------------------------------------
# Fixtures: temp files for collectors
# ---------------------------------------------------------------------------

@pytest.fixture
def log_file_factory(tmp_path):
    def _make(contents, name="test.log"):
        p = tmp_path / name
        p.write_text(contents, encoding="utf-8")
        return str(p)
    return _make
