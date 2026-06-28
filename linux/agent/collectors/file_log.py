import logging
from datetime import datetime, timezone
import json
from pathlib import Path

from collectors.base import CollectorBase

logger = logging.getLogger("vant-siem-agent")


class FileLogCollector(CollectorBase):
    source_type = "file_log"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._offsets = {}
        self._initialized = set()
        self._processed_ids = {}

    def _collect_from_path(self, item):
        path_str = item.get("path", "")
        path = Path(path_str)
        is_directory = item.get("type", "file") == "directory" or path_str.endswith("*")

        if is_directory:
            dir_path = path_str.rstrip("*").rstrip(" ").rstrip("\\").rstrip("/")
            base_path = Path(dir_path) if dir_path else path.parent
            if not base_path.is_dir():
                return []
            files = []
            for p in base_path.iterdir():
                if p.is_file():
                    files.append(p)
        elif path.exists() and path.is_file():
            files = [path]
        elif path.exists() and path.is_dir():
            files = [p for p in path.iterdir() if p.is_file()]
        else:
            return []

        all_events = []
        for fpath in files:
            all_events.extend(self._collect_from_file(fpath, item))
        return all_events

    def _try_parse_json(self, text):
        if text.startswith('\ufeff'):
            text = text[1:]
        stripped = text.strip()
        if not stripped:
            return None, None

        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return "json_array", parsed
            except (json.JSONDecodeError, ValueError):
                pass

        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return "json_object", parsed
            except (json.JSONDecodeError, ValueError):
                pass

        lines = text.splitlines()
        json_objects = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        json_objects.append(obj)
                except (json.JSONDecodeError, ValueError):
                    break
            else:
                break
        if json_objects and len(json_objects) == len([l for l in lines if l.strip()]):
            return "jsonl", json_objects

        return None, None

    def _is_already_processed(self, obj):
        event_id = obj.get("id") or obj.get("event_id")
        if event_id is None:
            return False
        key = str(event_id)
        if key in self._processed_ids:
            return True
        return False

    def _mark_as_processed(self, obj):
        event_id = obj.get("id") or obj.get("event_id")
        if event_id is not None:
            self._processed_ids[str(event_id)] = True

    def _collect_from_file(self, path, item):
        key = str(path.resolve())
        offset = int(self._offsets.get(key, 0))
        try:
            if path.stat().st_size < offset:
                offset = 0
                self._initialized.discard(key)
        except Exception:
            return []

        is_json_file = path.suffix.lower() in ('.json', '.jsonl')

        try:
            with path.open("rb") as fh:
                if key not in self._initialized:
                    self._initialized.add(key)
                    if str(item.get("start_position", "end")).lower() == "end":
                        fh.seek(0, 2)
                        self._offsets[key] = fh.tell()
                        return []
                    elif is_json_file:
                        fh.seek(0)
                        raw = fh.read()
                        self._offsets[key] = fh.tell()
                    else:
                        fh.seek(offset)
                        raw = fh.read()
                        self._offsets[key] = fh.tell()
                else:
                    if is_json_file:
                        fh.seek(0)
                        raw = fh.read()
                    else:
                        fh.seek(offset)
                        raw = fh.read()
                        self._offsets[key] = fh.tell()
        except Exception:
            return []

        if not raw:
            return []

        text = raw.decode("utf-8-sig", errors="ignore")
        max_lines = int(item.get("max_lines_per_cycle", 400))
        now = datetime.now(timezone.utc).isoformat()
        source_name = item.get("source_name") or path.name
        category = item.get("event_category", "file.log")
        logger.info("file_log.collect path=%s event_category=%s", str(path), category)
        severity = item.get("severity", "info")
        tags = item.get("tags", ["file", "log"])

        if is_json_file:
            json_type, json_data = self._try_parse_json(text)

            if json_type == "json_array" and isinstance(json_data, list):
                events = []
                new_events = [obj for obj in json_data if not self._is_already_processed(obj)]
                if len(new_events) > max_lines:
                    new_events = new_events[-max_lines:]
                for obj in new_events:
                    if not isinstance(obj, dict):
                        continue
                    event = {
                        "source_type": self.source_type,
                        "source_name": source_name,
                        "host_name": self.agent_cfg.get("host_name", ""),
                        "host_ip": self._host_ip,
                        "event_time": obj.get("timestamp", obj.get("event_time", now)),
                        "severity": obj.get("severity", severity),
                        "event_category": obj.get("event_category", obj.get("event_type", category)),
                        "message": json.dumps(obj.get("description", obj.get("message", obj)))[:1024],
                        "raw_payload": obj,
                        "tags": obj.get("tags", tags),
                    }
                    events.append(event)
                    self._mark_as_processed(obj)
                return events

            if json_type == "json_object" and isinstance(json_data, dict):
                if not self._is_already_processed(json_data):
                    event = {
                        "source_type": self.source_type,
                        "source_name": source_name,
                        "host_name": self.agent_cfg.get("host_name", ""),
                        "host_ip": self._host_ip,
                        "event_time": json_data.get("timestamp", json_data.get("event_time", now)),
                        "severity": json_data.get("severity", severity),
                        "event_category": json_data.get("event_category", json_data.get("event_type", category)),
                        "message": json.dumps(json_data.get("description", json_data.get("message", json_data)))[:1024],
                        "raw_payload": json_data,
                        "tags": json_data.get("tags", tags),
                    }
                    self._mark_as_processed(json_data)
                    return [event]
                return []

            if json_type == "jsonl" and isinstance(json_data, list):
                events = []
                new_events = [obj for obj in json_data if not self._is_already_processed(obj)]
                if len(new_events) > max_lines:
                    new_events = new_events[-max_lines:]
                for obj in new_events:
                    if not isinstance(obj, dict):
                        continue
                    event = {
                        "source_type": self.source_type,
                        "source_name": source_name,
                        "host_name": self.agent_cfg.get("host_name", ""),
                        "host_ip": self._host_ip,
                        "event_time": obj.get("timestamp", obj.get("event_time", now)),
                        "severity": obj.get("severity", severity),
                        "event_category": obj.get("event_category", obj.get("event_type", category)),
                        "message": json.dumps(obj.get("description", obj.get("message", obj)))[:1024],
                        "raw_payload": obj,
                        "tags": obj.get("tags", tags),
                    }
                    events.append(event)
                    self._mark_as_processed(obj)
                return events

        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[-max_lines:]

        events = []
        for line in lines:
            if not line.strip():
                continue
            events.append(
                {
                    "source_type": self.source_type,
                    "source_name": source_name,
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "event_time": now,
                    "severity": severity,
                    "event_category": category,
                    "message": line[:1024],
                    "raw_payload": {"line": line, "path": str(path)},
                    "tags": tags,
                }
            )
        logger.info("file_log.returning path=%s events=%d", str(path), len(events))
        return events

    def collect(self):
        items = self.cfg.get("items", [])
        if not items:
            items = self.cfg.get("sources", [])
        if not isinstance(items, list):
            return []
        events = []
        logger.info("file_log.collect_start items=%d", len(items))
        for item in items:
            if not isinstance(item, dict):
                continue
            if not item.get("enabled", True):
                continue
            events.extend(self._collect_from_path(item))
        logger.info("file_log.collect_done total_events=%d", len(events))
        return events
