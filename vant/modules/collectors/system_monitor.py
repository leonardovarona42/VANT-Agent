"""Monitor de procesos del sistema (Linux/Windows)"""
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


class SystemMonitorCollector(CollectorBase):
    source_type = "system_monitor"

    def collect(self):
        procs_cfg = self.cfg.get("processes", {})
        if not procs_cfg.get("enabled", True):
            return []
        max_procs = int(procs_cfg.get("max_processes", 50))
        sort_by = procs_cfg.get("sort_by", "cpu")

        if sys.platform.startswith("win"):
            return self._collect_windows(max_procs)
        return self._collect_linux(max_procs, sort_by)

    def _collect_windows(self, max_procs):
        ps_cmd = (
            "Get-Process | Sort-Object CPU -Descending | "
            "Select-Object -First {} Id, ProcessName, ".format(max_procs) +
            "@{N='cpu_percent';E={[math]::Round($_.CPU,1)}}, "
            "@{N='memory_mb';E={[math]::Round($_.WorkingSet64/1MB,1)}} | "
            "ConvertTo-Json -Compress"
        )
        result = _run_hidden([
            "powershell", "-NoProfile", "-Command", ps_cmd,
        ], timeout=20)
        if not result or result.returncode != 0:
            return []
        import json
        try:
            procs = json.loads(result.stdout)
            if isinstance(procs, dict):
                procs = [procs]
        except Exception:
            return []
        now = datetime.now(timezone.utc).isoformat()
        events = []
        for p in procs:
            events.append({
                "source_type": self.source_type,
                "source_name": "system_monitor",
                "host_name": self.agent_cfg.get("host_name", ""),
                "event_time": now,
                "severity": "info",
                "event_category": "system.process",
                "message": f"Process: {p.get('ProcessName', '')} (PID: {p.get('Id', '')})",
                "raw_payload": {
                    "pid": p.get("Id", 0),
                    "name": p.get("ProcessName", ""),
                    "cpu_percent": p.get("cpu_percent", 0),
                    "memory_mb": p.get("memory_mb", 0),
                },
                "tags": ["system", "process"],
            })
        return events

    def _collect_linux(self, max_procs, sort_by):
        sort_flag = "-%cpu" if sort_by == "cpu" else "-%mem"
        result = _run_hidden(
            ["ps", "aux", f"--sort={sort_flag}"], timeout=15,
        )
        if not result or result.returncode != 0:
            return []
        lines = result.stdout.strip().split("\n")[1:max_procs+1]
        now = datetime.now(timezone.utc).isoformat()
        events = []
        for line in lines:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            try:
                events.append({
                    "source_type": self.source_type,
                    "source_name": "system_monitor",
                    "host_name": self.agent_cfg.get("host_name", ""),
                    "event_time": now,
                    "severity": "info",
                    "event_category": "system.process",
                    "message": f"Process: {parts[10][:100]} (PID: {parts[1]})",
                    "raw_payload": {
                        "pid": int(parts[1]),
                        "name": parts[10][:100],
                        "cpu_percent": float(parts[2]),
                        "memory_mb": round(float(parts[3]) * 1024 / 1024, 1),
                    },
                    "tags": ["system", "process"],
                })
            except (ValueError, IndexError):
                continue
        return events
