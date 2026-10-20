from pathlib import Path

import pytest
import yaml

from vant.config import load_config, _deep_merge, find_config, save_config, DEFAULTS


class TestDeepMerge:
    def test_flat_override(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3}
        assert _deep_merge(base, override) == {"a": 1, "b": 3}

    def test_nested_merge(self):
        base = {"server": {"url": "http://a", "port": 80}}
        override = {"server": {"url": "http://b"}}
        result = _deep_merge(base, override)
        assert result["server"]["url"] == "http://b"
        assert result["server"]["port"] == 80

    def test_new_key_added(self):
        base = {"a": 1}
        override = {"b": 2}
        assert _deep_merge(base, override) == {"a": 1, "b": 2}

    def test_none_override_removes_key(self):
        base = {"a": 1, "b": 2}
        override = {"b": None}
        assert _deep_merge(base, override) == {"a": 1, "b": None}

    def test_list_is_replaced_not_merged(self):
        base = {"items": [1, 2]}
        override = {"items": [3]}
        assert _deep_merge(base, override) == {"items": [3]}

    def test_empty_override(self):
        base = {"a": 1}
        assert _deep_merge(base, {}) == {"a": 1}

    def test_original_not_mutated(self):
        base = {"a": {"b": 1}}
        override = {"a": {"c": 2}}
        original_a = base["a"]
        _deep_merge(base, override)
        assert base["a"] is original_a


class TestLoadConfig:
    def test_loads_valid_yaml(self, sample_config_path, sample_config_dict):
        cfg = load_config(sample_config_path)
        assert cfg["server"]["url"] == sample_config_dict["server"]["url"]
        assert cfg["agent"]["host_name"] == "test-pc"

    def test_merges_with_defaults(self, sample_config_path):
        cfg = load_config(sample_config_path)
        for key in DEFAULTS:
            assert key in cfg

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_empty_yaml_uses_defaults(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("", encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg == DEFAULTS

    def test_partial_config_merges(self, tmp_path):
        p = tmp_path / "partial.yaml"
        p.write_text(yaml.dump({"agent": {"host_name": "partial-test"}}), encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg["agent"]["host_name"] == "partial-test"
        assert cfg["server"]["url"] == DEFAULTS["server"]["url"]

    def test_preserves_unknown_keys(self, tmp_path):
        p = tmp_path / "custom.yaml"
        p.write_text(yaml.dump({"custom_key": "custom_value"}), encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg["custom_key"] == "custom_value"


class TestFindConfig:
    def test_local_config_exists(self, tmp_path):
        original = Path.cwd()
        try:
            import os
            os.chdir(tmp_path)
            cfg_file = tmp_path / "config.yaml"
            cfg_file.write_text("agent: {}", encoding="utf-8")
            result = find_config()
            # find_config returns relative "config.yaml" when cwd has it
            assert result == "config.yaml"
        finally:
            os.chdir(original)

    def test_returns_none_when_not_found(self, tmp_path):
        original = Path.cwd()
        try:
            import os
            os.chdir(tmp_path)
            assert find_config() is None
        finally:
            os.chdir(original)


class TestSaveConfig:
    def test_saves_and_reloads(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(yaml.dump({"agent": {"host_name": "original"}}), encoding="utf-8")

        save_config(str(p), {"agent": {"host_name": "updated"}})
        reloaded = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert reloaded["agent"]["host_name"] == "updated"

    def test_adds_new_section(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text(yaml.dump({"agent": {}}), encoding="utf-8")

        save_config(str(p), {"inventory": {"enabled": True}})
        reloaded = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert reloaded["inventory"]["enabled"] is True
        assert "agent" in reloaded

    def test_creates_file_if_not_exists(self, tmp_path):
        p = tmp_path / "new_config.yaml"
        save_config(str(p), {"test": True})
        reloaded = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert reloaded["test"] is True
