from vant.modules.collectors.base import CollectorBase
import subprocess
import json
import os
import time
from pathlib import Platform
from typing import List, Dict, Any


class VulnscanCollector(CollectorBase):
    source_type = "vulnscan"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self.state_dir = Path(__file__).resolve().parents[2] / ".vant_state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "vulnscan_state.json"
        self.state = self._load_state()
        self.interval = float(agent_cfg.get("interval_seconds", 300))  # default 5 min
        self.last_run = 0

    def _load_state(self) -> Dict[str, Any]:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self):
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
        except Exception:
            pass

    def _get_installed_kbs(self) -> List[str]:
        """Return list of installed KB article numbers (e.g., ['KB5001234'])."""
        try:
            # wmic qfe get HotFixID
            output = subprocess.check_output(
                ["wmic", "qfe", "get", "HotFixID", "/format:csv"],
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                text=True,
            )
            lines = output.strip().split("\n")
            kbs = []
            for line in lines[1:]:  # skip header
                parts = line.split(",")
                if len(parts) >= 2 and parts[1]:
                    kb = parts[1].strip()
                    if kb.startswith("KB"):
                        kbs.append(kb)
            return kbs
        except Exception:
            return []

    def _get_installed_software(self) -> List[Dict[str, str]]:
        """Return list of installed software with name and version via wmic product."""
        try:
            output = subprocess.check_output(
                ["wmic", "product", "get", "Name,Version", "/format:csv"],
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                text=True,
            )
            lines = output.strip().split("\n")
            software = []
            for line in lines[1:]:
                parts = line.split(",")
                if len(parts) >= 3:
                    name = parts[1].strip()
                    version = parts[2].strip()
                    if name and version:
                        software.append({"name": name, "version": version})
            return software
        except Exception:
            return []

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self.cfg or {}
        vuln_cfg = cfg.get("vulnscan", {})
        if not vuln_cfg.get("enabled", True):
            return []

        # Throttle: only run if enough time passed since last run
        now = time.time()
        if now - self.last_run < self.interval:
            return []
        self.last_run = now

        events = []

        # Check for missing KBs
        required_kbs = vuln_cfg.get("required_kbs", [])
        if isinstance(required_kbs, str):
            required_kbs = [required_kbs]
        installed_kbs = self._get_installed_kbs()
        missing_kbs = [kb for kb in required_kbs if kb not in installed_kbs]
        for kb in missing_kbs:
            events.append({
                "source_type": self.source_type,
                "source_name": "vulnscan",
                "event_category": "vuln.missing_kb",
                "message": f"Missing security update: {kb}",
                "severity": "high",
                "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "host_name": "",
                "host_ip": "",
                "raw_payload": {
                    "kb_id": kb,
                    "installed_kbs": installed_kbs
                },
                "tags": ["vuln", "missing_kb", kb]
            })

        # Check for vulnerable software versions
        vuln_software = vuln_cfg.get("vulnerable_software", [])
        # Expected format: [{"name": "Java", "max_version": "8u202"}, ...]
        installed_software = self._get_installed_software()
        for vuln_entry in vuln_software:
            name = vuln_entry.get("name", "")
            max_version = vuln_entry.get("max_version", "")
            if not name or not max_version:
                continue
            # Simple version comparison (string compare) - not robust but okay for demo
            for sw in installed_software:
                if sw["name"].lower() == name.lower():
                    # If installed version <= max_version considered vulnerable
                    # We'll use a simple string compare; in real scenario use packaging.version
                    if sw["version"] <= max_version:
                        events.append({
                            "source_type": self.source_type,
                            "source_name": "vulnscan",
                            "event_category": "vuln.vulnerable_software",
                            "message": f"Vulnerable software detected: {name} {sw['version']} (max safe: {max_version})",
                            "severity": "high",
                            "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "host_name": "",
                            "host_ip": "",
                            "raw_payload": {
                                "software_name": name,
                                "installed_version": sw["version"],
                                "max_safe_version": max_version
                            },
                            "tags": ["vuln", "vulnerable_software", name.lower()]
                        })

        if events:
            self._save_state()
        return events