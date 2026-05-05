from datetime import datetime, timezone
import subprocess

from collectors.base import CollectorBase


class WindowsEventLogCollector(CollectorBase):
    source_type = "windows_eventlog"

    def collect(self):
        channel = self.cfg.get("channel", "Security")
        # Minimal collector: last 20 events as text via PowerShell.
        # In production, move to win32evtlog subscription/bookmark mode.
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Get-WinEvent -LogName '{channel}' -MaxEvents 20 | "
            "Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json -Depth 3",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
            if result.returncode != 0 or not result.stdout.strip():
                return []
        except Exception:
            return []

        now = datetime.now(timezone.utc).isoformat()
        return [
            {
                "source_type": self.source_type,
                "source_name": channel,
                "host_name": self.agent_cfg.get("host_name", ""),
                "event_time": now,
                "severity": "info",
                "event_category": f"windows.eventlog.{channel.lower().replace(' ', '_')}",
                "message": f"Collected {channel} events",
                "raw_payload": {"channel": channel, "raw_json": result.stdout},
                "tags": ["windows", "eventlog", channel.lower().replace(" ", "_")],
            }
        ]

