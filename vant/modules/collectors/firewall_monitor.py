"""Monitor de reglas de firewall (Linux iptables/nftables, Windows netsh)"""
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


class FirewallMonitorCollector(CollectorBase):
    source_type = "firewall_monitor"

    def collect(self):
        fw_cfg = self.cfg.get("firewall", {})
        if not fw_cfg.get("enabled", True):
            return []

        if sys.platform.startswith("win"):
            return self._collect_windows()
        return self._collect_linux()

    def _collect_windows(self):
        result = _run_hidden([
            "powershell", "-NoProfile", "-Command",
            "Get-NetFirewallRule -Enabled True -PolicyStore ActiveStore | "
            "Select-Object Name,DisplayName,Enabled,Action,Direction | "
            "ConvertTo-Json -Compress",
        ], timeout=20)
        if not result or result.returncode != 0:
            return []
        import json
        try:
            rules = json.loads(result.stdout)
            if isinstance(rules, dict):
                rules = [rules]
        except Exception:
            return []
        now = datetime.now(timezone.utc).isoformat()
        return [{
            "source_type": self.source_type,
            "source_name": f"firewall.{r.get('Name', '')}",
            "host_name": self.agent_cfg.get("host_name", ""),
            "event_time": now,
            "severity": "info",
            "event_category": "system.firewall",
            "message": f"Rule: {r.get('DisplayName', '')} ({r.get('Action', '')})",
            "raw_payload": r,
            "tags": ["system", "firewall"],
        } for r in rules[:100]]

    def _collect_linux(self):
        result = _run_hidden(["iptables", "-L", "-n"], timeout=10)
        if not result or result.returncode != 0:
            result = _run_hidden(["nft", "list", "ruleset"], timeout=10)
            if not result or result.returncode != 0:
                return []
            raw = result.stdout
            fw_type = "nftables"
        else:
            raw = result.stdout
            fw_type = "iptables"

        now = datetime.now(timezone.utc).isoformat()
        lines = raw.strip().split("\n")
        return [{
            "source_type": self.source_type,
            "source_name": f"firewall.{fw_type}",
            "host_name": self.agent_cfg.get("host_name", ""),
            "event_time": now,
            "severity": "info",
            "event_category": "system.firewall",
            "message": line[:1024],
            "raw_payload": {"type": fw_type, "line": line},
            "tags": ["system", "firewall"],
        } for line in lines[:50]]
