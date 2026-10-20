import json

import pytest

from vant.modules.collectors.base import CollectorBase


class TestCollectorBase:
    def test_abstract_class_cannot_instantiate(self):
        with pytest.raises(TypeError):
            CollectorBase({}, {})

    def test_concrete_subclass(self):
        class TestCollector(CollectorBase):
            source_type = "test"

            def collect(self):
                return [{"event": "test"}]

        tc = TestCollector({"key": "val"}, {"host_name": "pc1"})
        assert tc.source_type == "test"
        assert tc.collect() == [{"event": "test"}]
        assert tc.cfg == {"key": "val"}
        assert tc.agent_cfg == {"host_name": "pc1"}

    def test_defaults_to_empty_dicts(self):
        class TC(CollectorBase):
            source_type = "t"
            def collect(self):
                return []

        tc = TC(None, None)
        assert tc.cfg == {}
        assert tc.agent_cfg == {}


class TestFileLogCollector:
    @pytest.fixture
    def collector(self):
        from vant.modules.collectors.file_log import FileLogCollector
        cfg = {
            "items": [],
            "enabled": True,
        }
        agent_cfg = {"host_name": "test-pc"}
        return FileLogCollector(cfg, agent_cfg)

    def test_source_type(self, collector):
        assert collector.source_type == "file_log"

    def test_no_items_returns_empty(self, collector):
        assert collector.collect() == []

    def test_collects_plain_text_lines(self, collector, tmp_path):
        log = tmp_path / "app.log"
        log.write_text("line1\nline2\nline3\n", encoding="utf-8")
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning"}]
        events = collector.collect()
        assert len(events) == 3
        assert events[0]["message"] == "line1"
        assert events[0]["source_type"] == "file_log"

    def test_jsonl_collection(self, collector, tmp_path):
        log = tmp_path / "data.jsonl"
        log.write_text(
            '{"id": "1", "message": "event1"}\n{"id": "2", "message": "event2"}\n',
            encoding="utf-8",
        )
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning"}]
        events = collector.collect()
        assert len(events) == 2
        assert events[0]["raw_payload"]["id"] == "1"

    def test_json_array_collection(self, collector, tmp_path):
        log = tmp_path / "batch.json"
        log.write_text(
            json.dumps([{"id": "a", "message": "first"}, {"id": "b", "message": "second"}]),
            encoding="utf-8",
        )
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning"}]
        events = collector.collect()
        assert len(events) == 2
        assert events[1]["raw_payload"]["id"] == "b"

    def test_tail_mode_starts_at_end(self, collector, tmp_path):
        log = tmp_path / "tail.log"
        log.write_text("old line\n", encoding="utf-8")
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "end"}]
        events = collector.collect()
        assert len(events) == 0  # starts at end, reads nothing new

        # Add new content and collect again
        log.write_text("old line\nnew line\n", encoding="utf-8")
        events = collector.collect()
        assert len(events) == 1
        assert "new" in events[0]["message"]

    def test_deduplicates_json_ids(self, collector, tmp_path):
        log = tmp_path / "dedup.json"
        log.write_text(
            json.dumps([{"id": "dup1", "data": "x"}, {"id": "dup1", "data": "y"}]),
            encoding="utf-8",
        )
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning"}]
        events = collector.collect()
        assert len(events) == 1  # deduplicated by id

    def test_respects_max_lines(self, collector, tmp_path):
        log = tmp_path / "many.log"
        log.write_text("\n".join([f"line{i}" for i in range(1000)]), encoding="utf-8")
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning", "max_lines_per_cycle": 50}]
        events = collector.collect()
        assert len(events) == 50

    def test_skips_disabled_item(self, collector, tmp_path):
        log = tmp_path / "skip.log"
        log.write_text("data\n", encoding="utf-8")
        collector.cfg["items"] = [
            {"path": str(log), "type": "file", "enabled": False},
        ]
        assert collector.collect() == []

    def test_handles_missing_file(self, collector):
        collector.cfg["items"] = [{"path": "/nonexistent/file.log", "type": "file"}]
        assert collector.collect() == []

    def test_directory_collection(self, collector, tmp_path):
        d = tmp_path / "logdir"
        d.mkdir()
        (d / "a.log").write_text("aaa\n", encoding="utf-8")
        (d / "b.log").write_text("bbb\n", encoding="utf-8")
        collector.cfg["items"] = [{"path": str(d), "type": "directory"}]
        events = collector.collect()
        assert len(events) == 2

    def test_source_name_uses_filename_by_default(self, collector, tmp_path):
        log = tmp_path / "myapp.log"
        log.write_text("test\n", encoding="utf-8")
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning"}]
        events = collector.collect()
        assert events[0]["source_name"] == "myapp.log"

    def test_custom_source_name(self, collector, tmp_path):
        log = tmp_path / "app.log"
        log.write_text("test\n", encoding="utf-8")
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning", "source_name": "custom-source"}]
        events = collector.collect()
        assert events[0]["source_name"] == "custom-source"

    def test_host_name_in_event(self, collector, tmp_path):
        log = tmp_path / "host.log"
        log.write_text("test\n", encoding="utf-8")
        collector.cfg["items"] = [{"path": str(log), "type": "file", "start_position": "beginning"}]
        events = collector.collect()
        assert events[0]["host_name"] == "test-pc"
