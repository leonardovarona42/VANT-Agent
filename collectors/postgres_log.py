from datetime import datetime, timezone
from pathlib import Path

from collectors.base import CollectorBase


class PostgresLogCollector(CollectorBase):
    source_type = "postgres"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._offset = 0
        self._initialized = False

    def collect(self):
        path = Path(self.cfg.get("path", ""))
        if not path.exists():
            return []

        with path.open("rb") as fh:
            fh_stat = fh.stat()
            if fh_stat.st_size < self._offset:
                self._offset = 0
                self._initialized = False
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
        raw = raw[:512 * 1024]
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
                    "source_name": "postgresql",
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "host_ip": self._host_ip,
                    "event_time": datetime.now(timezone.utc).isoformat(),
                    "severity": "info",
                    "event_category": "db.postgres.log",
                    "message": line[:1024],
                    "raw_payload": {"line": line},
                    "tags": ["db", "postgresql"],
                }
            )
        return events
