import subprocess
import time
import re
from datetime import datetime, timezone
from pathlib import Path
from collectors.base import CollectorBase

class FirewallMonitorCollector(CollectorBase):
    source_type = "firewall_monitor"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._last_collect = 0
        self._last_position = 0

    def collect(self):
        now = time.time()
        interval = int(self.cfg.get("interval", 60))
        if now - self._last_collect < interval:
            return []
        self._last_collect = now

        log_path = self.cfg.get("log_path", "/var/log/nftables.log")
        path = Path(log_path)
        if not path.exists():
            return []

        if path.stat().st_size < self._last_position:
            self._last_position = 0

        with path.open("rb") as fh:
            fh.seek(self._last_position)
            raw = fh.read()
            self._last_position = fh.tell()

        if not raw:
            return []

        max_lines = int(self.cfg.get("max_lines", 200))
        lines = raw.decode("utf-8", errors="ignore").splitlines()
        if len(lines) > max_lines:
            lines = lines[-max_lines:]

        ts = datetime.now(timezone.utc).isoformat()
        host = self.agent_cfg.get("host_name", "")
        events = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Parse nftables log line
            entry = {"raw": line[:512], "source": "nftables"}

            # Extract common fields from nftables log
            m = re.search(r"IN=(\S+)", line)
            if m:
                entry["in_interface"] = m.group(1)
            m = re.search(r"OUT=(\S+)", line)
            if m:
                entry["out_interface"] = m.group(1)
            m = re.search(r"MAC=(\S+)", line)
            if m:
                entry["mac"] = m.group(1)
            m = re.search(r"SRC=(\S+)", line)
            if m:
                entry["src_ip"] = m.group(1)
            m = re.search(r"DST=(\S+)", line)
            if m:
                entry["dst_ip"] = m.group(1)
            m = re.search(r"PROTO=(\S+)", line)
            if m:
                entry["protocol"] = m.group(1).upper()
            m = re.search(r"SPT=(\d+)", line)
            if m:
                entry["src_port"] = m.group(1)
            m = re.search(r"DPT=(\d+)", line)
            if m:
                entry["dst_port"] = m.group(1)

            severity = "low"
            event_category = "firewall.log"
            if "NFTABLES-INPUT" in line:
                event_category = "firewall.input"
                severity = "medium"
            elif "NFTABLES-FORWARD" in line:
                event_category = "firewall.forward"

            events.append({
                "source_type": self.source_type,
                "source_name": "firewall_monitor",
                "host_name": host,
                "host_ip": self._host_ip,
                "event_time": ts,
                "severity": severity,
                "event_category": event_category,
                "message": line[:1024],
                "raw_payload": entry,
                "tags": ["firewall", "nftables"],
            })

        return events
