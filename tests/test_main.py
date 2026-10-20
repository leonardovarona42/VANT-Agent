import pytest

from vant.main import (
    _ensure_host_fields,
    build_collectors,
    AGENT_VERSION,
)


class TestEnsureHostFields:
    def test_adds_host_name_if_missing(self):
        event = {}
        result = _ensure_host_fields(event, "my-host", "10.0.0.1")
        assert result["host_name"] == "my-host"

    def test_does_not_overwrite_host_name(self):
        event = {"host_name": "existing"}
        result = _ensure_host_fields(event, "my-host", "10.0.0.1")
        assert result["host_name"] == "existing"

    def test_adds_host_ip_to_raw_payload(self):
        event = {}
        result = _ensure_host_fields(event, "host", "10.0.0.1")
        assert result["raw_payload"]["host_ip"] == "10.0.0.1"

    def test_adds_host_name_to_raw_payload(self):
        event = {}
        result = _ensure_host_fields(event, "my-host", "10.0.0.1")
        assert result["raw_payload"]["host_name"] == "my-host"

    def test_preserves_existing_raw_payload(self):
        event = {"raw_payload": {"existing": "data"}}
        result = _ensure_host_fields(event, "host", "10.0.0.1")
        assert result["raw_payload"]["existing"] == "data"
        assert result["raw_payload"]["host_name"] == "host"

    def test_handles_non_dict_raw_payload(self):
        event = {"raw_payload": "string_data"}
        result = _ensure_host_fields(event, "host", "10.0.0.1")
        assert isinstance(result["raw_payload"], dict)
        assert result["raw_payload"]["host_name"] == "host"

    def test_empty_host_does_not_set(self):
        event = {}
        result = _ensure_host_fields(event, "", "")
        assert result.get("host_name") == ""
        assert result["raw_payload"].get("host_name") is None
        assert result["raw_payload"].get("host_ip") is None


class TestBuildCollectors:
    def test_returns_empty_list_with_no_collectors(self):
        cfg = {"collectors": {}}
        result = build_collectors(cfg, None)
        assert result == []

    def test_returns_empty_when_all_disabled(self, sample_config_dict):
        result = build_collectors(sample_config_dict, None)
        assert result == []

    def test_builds_snort_collector(self, mocker):
        cfg = {"collectors": {"snort": {"enabled": True, "path": "/var/log/snort"}}, "agent": {}}
        mock_snort = mocker.patch("vant.modules.collectors.snort.SnortCollector")
        result = build_collectors(cfg, None)
        assert len(result) == 1

    def test_builds_suricata_collector(self, mocker):
        cfg = {"collectors": {"suricata": {"enabled": True, "path": "/var/log/suricata"}}, "agent": {}}
        mock_suricata = mocker.patch("vant.modules.collectors.suricata.SuricataCollector")
        result = build_collectors(cfg, None)
        assert len(result) == 1

    def test_builds_file_log_collector(self, mocker):
        cfg = {"collectors": {"file_logs": {"enabled": True, "items": [{"path": "/tmp/test.log"}]}}, "agent": {}}
        mock_filelog = mocker.patch("vant.modules.collectors.file_log.FileLogCollector")
        result = build_collectors(cfg, None)
        assert len(result) == 1

    def test_handles_collector_import_error(self, mocker):
        cfg = {"collectors": {"snort": {"enabled": True, "path": "/tmp"}}, "agent": {}}
        mocker.patch("vant.modules.collectors.snort.SnortCollector", side_effect=Exception("import failed"))
        # Should catch the exception and log a warning, returning empty list
        result = build_collectors(cfg, None)
        assert result == []

    def test_windows_eventlog_channels_expansion(self, mocker):
        cfg = {
            "collectors": {
                "windows_eventlog": {
                    "enabled": True,
                    "channels": ["Security", "System"],
                }
            },
            "agent": {},
        }
        mocker.patch("vant.modules.collectors.windows_eventlog.WindowsEventLogCollector")
        result = build_collectors(cfg, None)
        # Channels without path separators, so each becomes a separate collector
        assert len(result) == 2

    def test_windows_eventlog_skips_invalid_channels(self, mocker):
        cfg = {
            "collectors": {
                "windows_eventlog": {
                    "enabled": True,
                    "channels": ["Security", "C:\\Custom\\Channel", "*"],
                }
            },
            "agent": {},
        }
        mock_wel = mocker.patch("vant.modules.collectors.windows_eventlog.WindowsEventLogCollector")
        result = build_collectors(cfg, None)
        # Only "Security" should remain (backslash, forward slash, and wildcard filtered)
        wel_calls = mock_wel.call_args_list
        channels_used = [c[0][0].get("channel") for c in wel_calls]
        assert "Security" in channels_used
        assert "C:\\Custom\\Channel" not in channels_used
        assert "*" not in channels_used

    def test_postgres_collector(self, mocker):
        cfg = {"collectors": {"postgres": {"enabled": True, "path": "/var/log/postgresql"}}, "agent": {}}
        mocker.patch("vant.modules.collectors.postgres_log.PostgresLogCollector")
        result = build_collectors(cfg, None)
        assert len(result) == 1
