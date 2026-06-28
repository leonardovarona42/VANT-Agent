import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from collectors.base import CollectorBase

class ServiceMonitorCollector(CollectorBase):
    source_type = "service_monitor"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self._last_collect = 0

    def _run_cmd(self, cmd, timeout=15):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                return r.stdout
        except Exception:
            pass
        return ""

    def list_available_services(self):
        """List all available systemd services for installer selection."""
        raw = self._run_cmd([
            "systemctl", "list-units", "--type=service",
            "--all", "--no-pager", "--no-legend", "--plain"
        ])
        services = []
        for line in raw.strip().split(chr(10)):
            parts = line.split(None, 4)
            if len(parts) >= 4:
                name = parts[0].strip()
                load = parts[1].strip()
                active = parts[2].strip()
                sub = parts[3].strip()
                desc = parts[4].strip() if len(parts) > 4 else ""
                services.append({
                    "name": name,
                    "load": load,
                    "active": active,
                    "sub": sub,
                    "description": desc,
                })
        return services

    def get_service_status(self, service_name):
        """Get detailed status for a specific service."""
        raw = self._run_cmd(["systemctl", "show", service_name, "--no-pager"])
        info = {}
        for line in raw.strip().split(chr(10)):
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v
        return {
            "name": service_name,
            "active_state": info.get("ActiveState", ""),
            "sub_state": info.get("SubState", ""),
            "load_state": info.get("LoadState", ""),
            "pid": info.get("MainPID", ""),
            "cpu_usage": info.get("CPUUsageNSec", ""),
            "memory_current": info.get("MemoryCurrent", ""),
            "tasks_current": info.get("TasksCurrent", ""),
            "description": info.get("Description", ""),
        }

    def collect(self):
        now = time.time()
        interval = int(self.cfg.get("interval", 120))
        if now - self._last_collect < interval:
            return []
        self._last_collect = now

        selected = self.cfg.get("services", [])
        if not selected:
            return []

        ts = datetime.now(timezone.utc).isoformat()
        host = self.agent_cfg.get("host_name", "")

        services_data = []
        for svc in selected:
            name = svc.get("name", "") if isinstance(svc, dict) else svc
            if not name:
                continue
            status = self.get_service_status(name)
            services_data.append(status)

        if not services_data:
            return []

        return [{
            "source_type": self.source_type,
            "source_name": "service_monitor",
            "host_name": host,
            "host_ip": self._host_ip,
            "event_time": ts,
            "severity": "info",
            "event_category": "system.services",
            "message": f"Monitored {len(services_data)} services",
            "raw_payload": {"services": services_data},
            "tags": ["system", "services"],
        }]


def list_services_for_installer():
    """Helper for the installer CLI to list services."""
    collector = ServiceMonitorCollector({}, {})
    return collector.list_available_services()


def format_services_table(services):
    """Format service list as a numbered table."""
    lines = []
    lines.append(f"{'#':>3}  {'SERVICE':<40} {'STATUS':<12} {'DESCRIPTION'}")
    lines.append("-" * 90)
    for i, svc in enumerate(services, 1):
        status = f"{svc['active']}/{svc['sub']}"
        desc = svc.get("description", "")[:50]
        lines.append(f"{i:>3}  {svc['name']:<40} {status:<12} {desc}")
    return chr(10).join(lines)
