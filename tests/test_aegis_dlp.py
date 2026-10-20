import pytest

import os

from vant.modules.dlp.aegis import (
    AegisDlpService,
    _expand_scan_paths,
    _utc_now,
    _sha256,
    _path_channel,
    _default_policy,
    _windows_fixed_drives,
    DEFAULT_DLP_EXTENSIONS,
    DEFAULT_DLP_KEYWORDS,
)


class TestAegisDlpInit:
    def test_creates_service(self, tmp_path):
        cfg = {"aegis_dlp": {"enabled": True}}
        svc = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        assert svc.module_name == "aegis_dlp"
        assert "known_drives" in svc.state or svc.state == {}

    def test_state_dir_created(self, tmp_path):
        cfg = {"aegis_dlp": {"enabled": True}}
        AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        state_dir = tmp_path / ".agent_state"
        assert state_dir.exists()

    def test_state_file_persists(self, tmp_path):
        cfg = {"aegis_dlp": {"enabled": True}}
        svc1 = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        svc1.state["test_key"] = "test_value"
        import json
        (tmp_path / ".agent_state" / "aegis_dlp_state.json").write_text(
            json.dumps(svc1.state), encoding="utf-8"
        )
        svc2 = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        assert svc2.state.get("test_key") == "test_value"


class TestExpandScanPaths:
    def test_expands_env_vars(self, mocker):
        mocker.patch.dict("os.environ", {"USERPROFILE": "C:\\Users\\test"}, clear=True)
        result = _expand_scan_paths(["%USERPROFILE%\\Desktop"])
        assert any("C:\\Users\\test\\Desktop" in str(r) for r in result)

    def test_deduplicates(self):
        paths = ["C:\\a", "C:\\a", "C:\\b"]
        result = _expand_scan_paths(paths)
        assert len(result) == 2

    def test_empty_paths_returns_empty(self):
        assert _expand_scan_paths([]) == []

    def test_skips_empty_after_expand(self, mocker):
        mocker.patch.dict("os.environ", {}, clear=True)
        result = _expand_scan_paths(["%NONEXISTENT%"])
        # On Windows, expandvars leaves unresolvable %vars% intact;
        # after Path() resolves them, the path is not empty, so it remains.
        if os.name == "nt":
            assert len(result) >= 1
        else:
            assert result == []


class TestWindowsFixedDrives:
    def test_returns_empty_on_linux(self, mocker):
        mocker.patch("os.name", "posix")
        assert _windows_fixed_drives() == []


class TestSha256:
    def test_computes_hash(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world", encoding="utf-8")
        h = _sha256(f)
        assert h == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        h = _sha256(f)
        assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_missing_file(self, tmp_path):
        import os
        f = tmp_path / "missing.txt"
        assert _sha256(f) == ""


class TestPathChannel:
    def test_downloads(self):
        assert _path_channel("C:\\Users\\test\\Downloads\\file.pdf") == "downloads"

    def test_desktop(self):
        assert _path_channel("C:\\Users\\test\\Desktop\\file.pdf") == "desktop"

    def test_documents(self):
        assert _path_channel("C:\\Users\\test\\Documents\\file.pdf") == "documents"

    def test_filesystem_default(self):
        assert _path_channel("C:\\Program Files\\app\\file.txt") == "filesystem"


class TestUtcNow:
    def test_returns_iso_format(self):
        now = _utc_now()
        assert "T" in now
        # Should end with timezone info or have Z/+00:00
        assert now.endswith("+00:00") or "+00:00" in now


class TestDefaultPolicy:
    def test_has_rules(self):
        policy = _default_policy()
        assert policy["code"] == "aegis-local-shield"
        assert len(policy["rules"]) > 0

    def test_includes_default_extensions(self):
        policy = _default_policy()
        for ext in DEFAULT_DLP_EXTENSIONS:
            assert ext in policy["monitored_extensions"]


class TestAegisDlpIncidentQueue:
    def test_queue_and_peek(self, tmp_path):
        svc = AegisDlpService(str(tmp_path / "config.yaml"), {"aegis_dlp": {"enabled": True}})
        incident = {"fingerprint": "abc123", "file_name": "test.txt"}
        svc.queue_incidents([incident])
        pending = svc.peek_pending_incidents()
        assert len(pending) == 1
        assert pending[0]["fingerprint"] == "abc123"

    def test_deduplicates_by_fingerprint(self, tmp_path):
        svc = AegisDlpService(str(tmp_path / "config.yaml"), {"aegis_dlp": {"enabled": True}})
        svc.queue_incidents([{"fingerprint": "dup"}, {"fingerprint": "dup"}])
        assert len(svc.peek_pending_incidents()) == 1

    def test_clear_pending(self, tmp_path):
        svc = AegisDlpService(str(tmp_path / "config.yaml"), {"aegis_dlp": {"enabled": True}})
        svc.queue_incidents([{"fingerprint": "abc"}])
        svc.clear_pending_incidents()
        assert svc.peek_pending_incidents() == []

    def test_max_5000_pending(self, tmp_path):
        svc = AegisDlpService(str(tmp_path / "config.yaml"), {"aegis_dlp": {"enabled": True}})
        incidents = [{"fingerprint": f"inc-{i}"} for i in range(6000)]
        svc.queue_incidents(incidents)
        assert len(svc.peek_pending_incidents()) == 5000


class TestAegisDlpScan:
    def test_disabled_returns_empty(self, tmp_path):
        cfg = {"aegis_dlp": {"enabled": False}}
        svc = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        assert svc.scan() == []

    def test_scans_txt_file_with_keyword(self, tmp_path):
        target = tmp_path / "docs"
        target.mkdir()
        f = target / "secret.txt"
        f.write_text("Este documento contiene informacion clasificada", encoding="utf-8")

        cfg = {"aegis_dlp": {"enabled": True}}
        svc = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        # Point scan at our temp dir
        svc.remote_config = {
            "policies": [{
                "code": "test-policy",
                "name": "Test",
                "severity": "high",
                "scan_paths": [str(target)],
                "monitored_extensions": [".txt"],
                "rules": [{
                    "name": "Test Rule",
                    "classification": "test",
                    "severity": "critical",
                    "match_type": "keyword",
                    "pattern": "informacion clasificada",
                    "tags": ["test"],
                }],
            }]
        }
        incidents = svc.scan()
        assert len(incidents) >= 1
        assert incidents[0]["classification"] == "test"

    def test_skips_unchanged_files(self, tmp_path):
        target = tmp_path / "docs"
        target.mkdir()
        f = target / "data.txt"
        f.write_text("informacion clasificada", encoding="utf-8")

        cfg = {"aegis_dlp": {"enabled": True}}
        svc = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        svc.remote_config = {
            "policies": [{
                "code": "test", "name": "Test", "severity": "high",
                "scan_paths": [str(target)],
                "monitored_extensions": [".txt"],
                "rules": [{"name": "R1", "classification": "c1", "severity": "high", "match_type": "keyword", "pattern": "clasificada", "tags": []}],
            }]
        }
        first = svc.scan()
        assert len(first) >= 1

        # Second scan should produce no new incidents (file unchanged)
        second = svc.scan()
        assert len(second) == 0

    def test_detects_new_file_after_change(self, tmp_path):
        target = tmp_path / "docs"
        target.mkdir()
        f = target / "data.txt"
        f.write_text("informacion clasificada", encoding="utf-8")

        cfg = {"aegis_dlp": {"enabled": True}}
        svc = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        svc.remote_config = {
            "policies": [{
                "code": "test", "name": "Test", "severity": "high",
                "scan_paths": [str(target)],
                "monitored_extensions": [".txt"],
                "rules": [{"name": "R1", "classification": "c1", "severity": "high", "match_type": "keyword", "pattern": "clasificada", "tags": []}],
            }]
        }
        svc.scan()

        f.write_text("informacion clasificada y otros datos", encoding="utf-8")
        second = svc.scan()
        assert len(second) >= 1

    def test_respects_max_file_size(self, tmp_path):
        target = tmp_path / "docs"
        target.mkdir()
        f = target / "big.txt"
        f.write_text("a" * (2 * 1024 * 1024), encoding="utf-8")  # 2MB (over 1MB limit)

        cfg = {"aegis_dlp": {"enabled": True, "max_file_size_mb": 1}}
        svc = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        svc.remote_config = {
            "policies": [{
                "code": "test", "name": "Test", "severity": "high",
                "scan_paths": [str(target)],
                "monitored_extensions": [".txt"],
                "rules": [{"name": "R1", "classification": "c1", "severity": "high", "match_type": "keyword", "pattern": "a"*5, "tags": []}],
            }]
        }
        incidents = svc.scan()
        assert len(incidents) == 0

    def test_scan_cache_persists(self, tmp_path):
        target = tmp_path / "docs"
        target.mkdir()
        f = target / "data.txt"
        f.write_text("informacion clasificada", encoding="utf-8")

        cfg = {"aegis_dlp": {"enabled": True}}
        svc = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        svc.remote_config = {
            "policies": [{
                "code": "test", "name": "Test", "severity": "high",
                "scan_paths": [str(target)],
                "monitored_extensions": [".txt"],
                "rules": [{"name": "R1", "classification": "c1", "severity": "high", "match_type": "keyword", "pattern": "clasificada", "tags": []}],
            }]
        }
        svc.scan()
        cache_key = str(f).lower()

        # New instance should have cache from state file
        svc2 = AegisDlpService(str(tmp_path / "config.yaml"), cfg)
        svc2.remote_config = svc.remote_config
        incidents = svc2.scan()
        assert len(incidents) == 0  # cached


class TestAegisDlpRemoteConfig:
    def test_fetch_remote_config_no_server(self, tmp_path):
        svc = AegisDlpService(str(tmp_path / "config.yaml"), {})
        result = svc.fetch_remote_config("", "token", "agent-1")
        assert result == {}

    def test_fetch_remote_config_success(self, tmp_path, mocker):
        svc = AegisDlpService(str(tmp_path / "config.yaml"), {})
        mocker.patch("requests.get", return_value=mocker.MagicMock(
            status_code=200,
            json=lambda: {"policies": [{"code": "remote-policy"}]}
        ))
        result = svc.fetch_remote_config("http://server", "token", "agent-1")
        assert result["policies"][0]["code"] == "remote-policy"

    def test_fetch_remote_config_failure(self, tmp_path, mocker):
        svc = AegisDlpService(str(tmp_path / "config.yaml"), {})
        mocker.patch("requests.get", side_effect=Exception("timeout"))
        result = svc.fetch_remote_config("http://server", "token", "agent-1")
        assert result == {}  # returns existing remote_config (empty)
