"""Monitor de servicios del sistema (systemd en Linux, Services en Windows)"""
import os
import subprocess
import sys
from datetime import datetime, timezone

from vant.modules.collectors.base import CollectorBase


def _run_hidden(cmd, timeout=15):
    try:
        if sys.platform.startswith("win"):
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            return subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                check=False, startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except Exception:
        return None


class ServiceMonitorCollector(CollectorBase):
    source_type = "service_monitor"

    def collect(self):
        svc_cfg = self.cfg.get("services", {})
        if not svc_cfg.get("enabled", True):
            return []
        monitored = svc_cfg.get("monitored_services", [])
        if sys.platform.startswith("win"):
            return self._collect_windows(monitored)
        return self._collect_linux(monitored)

    def _collect_linux(self, monitored):
        if monitored:
            events = []
            for svc in monitored:
                result = _run_hidden(
                    ["systemctl", "is-active", svc], timeout=10,
                )
                status = result.stdout.strip() if result else "unknown"
                now = datetime.now(timezone.utc).isoformat()
                events.append({
                    "source_type": self.source_type,
                    "source_name": f"service.{svc}",
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "event_time": now,
                    "severity": "error" if status != "active" else "info",
                    "event_category": "system.service",
                    "message": f"Service {svc}: {status}",
                    "raw_payload": {"service": svc, "status": status},
                    "tags": ["system", "service"],
                })
            return events

        result = _run_hidden(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-pager", "--no-legend"], timeout=15,
        )
        if not result or result.returncode != 0:
            return []
        now = datetime.now(timezone.utc).isoformat()
        events = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                events.append({
                    "source_type": self.source_type,
                    "source_name": f"service.{parts[0]}",
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "event_time": now,
                    "severity": "info",
                    "event_category": "system.service",
                    "message": f"Service {parts[0]}: {parts[2]}",
                    "raw_payload": {"service": parts[0], "status": parts[2],
                                   "description": " ".join(parts[3:])},
                    "tags": ["system", "service"],
                })
        return events

    def _collect_windows(self, monitored):
        if monitored:
            events = []
            for svc in monitored:
                result = _run_hidden([
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-Service -Name '{svc}' -ErrorAction SilentlyContinue).Status",
                ], timeout=10)
                status = result.stdout.strip() if result and result.returncode == 0 else "unknown"
                now = datetime.now(timezone.utc).isoformat()
                events.append({
                    "source_type": self.source_type,
                    "source_name": f"service.{svc}",
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "event_time": now,
                    "severity": "error" if status != "Running" else "info",
                    "event_category": "system.service",
                    "message": f"Service {svc}: {status}",
                    "raw_payload": {"service": svc, "status": status},
                    "tags": ["system", "service"],
                })
            return events
        result = _run_hidden([
            "powershell", "-NoProfile", "-Command",
            "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
            "Select-Object Name,DisplayName,Status | ConvertTo-Json -Compress",
        ], timeout=15)
        if not result or result.returncode != 0:
            return []
        import json
        try:
            services = json.loads(result.stdout)
            if isinstance(services, dict):
                services = [services]
        except Exception:
            return []
        now = datetime.now(timezone.utc).isoformat()
        return [{
            "source_type": self.source_type,
            "source_name": f"service.{s.get('Name', '')}",
            "host_name": self.agent_cfg.get("host_name", ""),
            "event_time": now,
            "severity": "info",
            "event_category": "system.service",
            "message": f"Service {s.get('DisplayName', '')}: Running",
            "raw_payload": s,
            "tags": ["system", "service"],
        } for s in services]
