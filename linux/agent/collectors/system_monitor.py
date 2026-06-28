import subprocess
import time
from datetime import datetime, timezone
from collectors.base import CollectorBase

class SystemMonitorCollector(CollectorBase):
    source_type = "system_monitor"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._last_collect = 0

    def _run_cmd(self, cmd, timeout=10):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                return r.stdout
        except Exception:
            pass
        return ""

    def _parse_ps(self, raw):
        lines = raw.strip().split(chr(10))
        if not lines or len(lines) < 2:
            return []
        procs = []
        for line in lines[1:]:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            try:
                procs.append({
                    "user": parts[0],
                    "pid": int(parts[1]),
                    "cpu": float(parts[2]),
                    "mem": float(parts[3]),
                    "vsz": parts[4],
                    "rss": parts[5],
                    "tty": parts[6],
                    "stat": parts[7],
                    "start": parts[8],
                    "time": parts[9],
                    "command": parts[10][:200],
                })
            except (ValueError, IndexError):
                continue
        return procs

    def _parse_ss_tcp(self, raw):
        lines = raw.strip().split(chr(10))
        if not lines or len(lines) < 2:
            return []
        conns = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                conns.append({
                    "state": parts[0],
                    "recv_q": parts[1],
                    "send_q": parts[2],
                    "local": parts[3],
                    "peer": parts[4],
                })
            except IndexError:
                continue
        return conns

    def _parse_listening(self, raw):
        lines = raw.strip().split(chr(10))
        if not lines or len(lines) < 2:
            return []
        ports = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[3]
            if ":" in local:
                addr, port = local.rsplit(":", 1)
                try:
                    int(port)
                    ports.append({
                        "address": addr,
                        "port": int(port),
                        "protocol": "tcp",
                    })
                except ValueError:
                    continue
        return ports

    def _collect_processes(self):
        raw = self._run_cmd(["ps", "aux", "--sort=-%cpu"])
        return self._parse_ps(raw)

    def _collect_connections(self):
        raw = self._run_cmd(["ss", "-tan"])
        return self._parse_ss_tcp(raw)

    def _collect_ports(self):
        raw = self._run_cmd(["ss", "-tlnp"])
        return self._parse_listening(raw)

    def collect(self):
        now = time.time()
        interval = int(self.cfg.get("interval", 60))
        if now - self._last_collect < interval:
            return []
        self._last_collect = now

        events = []
        ts = datetime.now(timezone.utc).isoformat()
        host = self.agent_cfg.get("host_name", "")

        if self.cfg.get("processes", {}).get("enabled", True):
            procs = self._collect_processes()
            top_n = int(self.cfg.get("processes", {}).get("top_n", 20))
            if len(procs) > top_n:
                procs = procs[:top_n]
            events.append({
                "source_type": self.source_type,
                "source_name": "system_monitor",
                "host_name": host,
                "host_ip": self._host_ip,
                "event_time": ts,
                "severity": "info",
                "event_category": "system.processes",
                "message": f"Top {len(procs)} processes by CPU",
                "raw_payload": {"processes": procs},
                "tags": ["system", "processes"],
            })

        if self.cfg.get("connections", {}).get("enabled", True):
            conns = self._collect_connections()
            established = [c for c in conns if c["state"] == "ESTAB"]
            events.append({
                "source_type": self.source_type,
                "source_name": "system_monitor",
                "host_name": host,
                "host_ip": self._host_ip,
                "event_time": ts,
                "severity": "info",
                "event_category": "system.connections",
                "message": f"{len(established)} established, {len(conns)} total connections",
                "raw_payload": {"connections": conns},
                "tags": ["system", "connections"],
            })

        if self.cfg.get("ports", {}).get("enabled", True):
            ports = self._collect_ports()
            events.append({
                "source_type": self.source_type,
                "source_name": "system_monitor",
                "host_name": host,
                "host_ip": self._host_ip,
                "event_time": ts,
                "severity": "info",
                "event_category": "system.ports",
                "message": f"{len(ports)} listening TCP ports",
                "raw_payload": {"ports": ports},
                "tags": ["system", "ports"],
            })

        return events
