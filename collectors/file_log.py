from datetime import datetime, timezone
from pathlib import Path

from collectors.base import CollectorBase


class FileLogCollector(CollectorBase):
    source_type = "file_log"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._offsets = {}
        self._initialized = set()

    def _collect_from_path(self, item):
        path = Path(item.get("path", ""))
        if not path.exists() or not path.is_file():
            return []

        key = str(path.resolve())
        offset = int(self._offsets.get(key, 0))
        if path.stat().st_size < offset:
            offset = 0
            self._initialized.discard(key)

        with path.open("rb") as fh:
            if key not in self._initialized:
                self._initialized.add(key)
                if str(item.get("start_position", "end")).lower() == "end":
                    fh.seek(0, 2)
                    self._offsets[key] = fh.tell()
                    return []
            fh.seek(offset)
            raw = fh.read()
            self._offsets[key] = fh.tell()

        if not raw:
            return []

        lines = raw.decode("utf-8", errors="ignore").splitlines()
        max_lines = int(item.get("max_lines_per_cycle", 400))
        if len(lines) > max_lines:
            lines = lines[-max_lines:]

        now = datetime.now(timezone.utc).isoformat()
        source_name = item.get("source_name") or path.name
        category = item.get("event_category", "file.log")
        severity = item.get("severity", "info")
        tags = item.get("tags", ["file", "log"])

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
        return events

    def collect(self):
        items = self.cfg.get("items", [])
        if not isinstance(items, list):
            return []
        events = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if not item.get("enabled", True):
                continue
            events.extend(self._collect_from_path(item))
        return events
