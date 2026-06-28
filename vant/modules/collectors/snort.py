from datetime import datetime, timezone
from pathlib import Path

from vant.modules.collectors.base import CollectorBase


class SnortCollector(CollectorBase):
    source_type = "snort"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._offset = 0
        self._initialized = False

    def _resolve_path(self):
        raw = str(self.cfg.get("path", "")).strip()
        if not raw:
            return Path()
        path = Path(raw)
        if path.is_dir():
            candidates = [
                path / "log" / "alerts.fast",
                path / "log" / "alert.fast",
                path / "alerts.fast",
                path / "alert.fast",
                path / "fast.log",
            ]
            for candidate in candidates:
                if candidate.exists():
                    return candidate
            for pattern in ("*.fast", "*.log", "*.txt"):
                matches = sorted(path.rglob(pattern))
                if matches:
                    return matches[0]
        return path

    def collect(self):
        path = self._resolve_path()
        if not path.exists():
            return []
        if path.stat().st_size < self._offset:
            self._offset = 0
            self._initialized = False

        with path.open("rb") as fh:
            if not self._initialized:
                self._initialized = True
                if str(self.cfg.get("start_position", "end")).lower() == "end":
                    fh.seek(0, 2)
                    self._offset = fh.tell()
                    return []
            fh.seek(self._offset)
            raw = fh.read()
            self._offset = fh.tell()

        if not raw:
            return []
        lines = raw.decode("utf-8", errors="ignore").splitlines()
        max_lines = int(self.cfg.get("max_lines_per_cycle", 400))
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        events = []
        for line in lines:
            if not line.strip():
                continue
            events.append(
                {
                    "source_type": self.source_type,
                    "source_name": "snort",
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "host_ip": self._host_ip,
                    "event_time": datetime.now(timezone.utc).isoformat(),
                    "severity": "medium",
                    "event_category": "ids.alert",
                    "message": line[:1024],
                    "raw_payload": {"line": line},
                    "tags": ["ids", "snort"],
                }
            )
        return events
