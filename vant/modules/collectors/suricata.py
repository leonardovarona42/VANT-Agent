import json
from datetime import datetime, timezone
from pathlib import Path

from collectors.base import CollectorBase


class SuricataCollector(CollectorBase):
    source_type = "suricata"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._offset = 0
        self._initialized = False

    def _truncate_payload(self, payload, max_bytes=50 * 1024):
        raw = json.dumps(payload, default=str)
        if len(raw) > max_bytes:
            return {"_truncated": True, "event_type": payload.get("event_type", ""), "timestamp": payload.get("timestamp", "")}
        return payload

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
        max_lines = int(self.cfg.get("max_lines_per_cycle", 600))
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        events = []
        for line in lines:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
            message = (
                payload.get("alert", {}).get("signature")
                or payload.get("event_type")
                or "suricata event"
            )
            events.append(
                {
                    "source_type": self.source_type,
                    "source_name": "suricata",
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "event_time": ts,
                    "severity": str(payload.get("alert", {}).get("severity", "")),
                    "event_category": payload.get("event_type", "ids.event"),
                    "message": message[:1024],
                    "raw_payload": self._truncate_payload(payload),
                    "tags": ["ids", "suricata"],
                }
            )
        return events
