import json
import os
import platform
import socket
import time
from pathlib import Path

from vant.utils import detect_host, detect_os, get_mac_address
from vant.modules.inventory.collector import (
    collect_windows_hardware, collect_windows_software,
    collect_linux_hardware, collect_linux_software,
    detect_os_type,
)


class InventoryService:
    def __init__(self, config):
        self.config = config
        self.agent_id = None
        self._state_dir = self._get_state_dir()
        self._load_state()

    def _get_state_dir(self):
        return Path(os.path.dirname(self.config.get("_config_path", "."))) / ".vant_state"

    def _load_state(self):
        state_file = self._state_dir / "inventory_state.json"
        self._state_dir.mkdir(parents=True, exist_ok=True)
        if state_file.exists():
            try:
                self._state = json.loads(state_file.read_text(encoding="utf-8"))
            except Exception:
                self._state = {}
        else:
            self._state = {}

    def _save_state(self):
        state_file = self._state_dir / "inventory_state.json"
        state_file.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    @property
    def config_version(self):
        return self._state.get("config_version", 0)

    @config_version.setter
    def config_version(self, value):
        self._state["config_version"] = value
        self._save_state()

    def register(self, client, logger):
        hostname, ip = detect_host()
        cfg = self.config.get("agent", {})
        os_type = detect_os()
        mac = get_mac_address()

        data = {
            "hostname": cfg.get("host_name", hostname) or hostname,
            "machine_name": platform.node(),
            "os_type": os_type,
            "os_version": platform.version(),
            "os_arch": platform.machine(),
            "agent_version": "1.1.0",
            "ip_address": ip or None,
            "mac_address": mac,
            "domain": "",
            "tags": ["vant-agent"],
        }

        try:
            resp = client.register_agent(data)
            if resp.status_code in (200, 201):
                result = resp.json()
                self.agent_id = result.get("agent_id")
                if self.agent_id:
                    self._state["agent_id"] = self.agent_id
                    self._save_state()
                auth_token = result.get("auth_token", "")
                if auth_token:
                    self._state["auth_token"] = auth_token
                    self._save_state()
                logger.info(
                    "inventory.registered id=%s created=%s has_token=%s",
                    self.agent_id, result.get("created", False), bool(auth_token),
                )
                return True
            else:
                logger.error("inventory.register failed status=%s", resp.status_code)
        except Exception as e:
            logger.error("inventory.register error: %s", e)
        return False

    def heartbeat(self, client, logger):
        if not self.agent_id:
            return
        _, ip = detect_host()
        try:
            resp = client.send_heartbeat(self.agent_id, ip, self.config_version)
            if resp.status_code == 200:
                data = resp.json()
                commands = data.get("commands", [])
                if commands:
                    logger.info("heartbeat got %d pending commands", len(commands))

                cfg_update = data.get("config_update") or {}
                if cfg_update.get("available"):
                    logger.info("config update available version=%s", cfg_update.get("version"))

                return data
        except Exception as e:
            logger.warning("heartbeat error=%s", e)
        return None

    def collect_and_submit(self, client, logger):
        if not self.agent_id:
            return False

        is_windows = os.name == "nt"

        if is_windows:
            hw = collect_windows_hardware()
            sw = collect_windows_software()
        else:
            hw = collect_linux_hardware()
            sw = collect_linux_software()

        hw_hash = self._hash_hw(hw)
        sw_hash = self._hash_sw(sw)
        prev_hw = self._state.get("hardware_hash")
        prev_sw = self._state.get("software_hash")
        first_time = prev_hw is None and prev_sw is None

        if not first_time and hw_hash == prev_hw and sw_hash == prev_sw:
            self._state["last_inventory"] = time.time()
            self._save_state()
            return False

        try:
            resp = client.submit_inventory(self.agent_id, hw, sw)
            if resp.status_code == 200:
                result = resp.json()
                logger.info(
                    "inventory.submitted hw=%s sw=%d changed=%s",
                    "changed" if hw_hash != prev_hw else "same",
                    result.get("software_count", len(sw)),
                    "yes" if sw_hash != prev_sw else "no",
                )
                self._state["last_inventory"] = time.time()
                self._state["hardware_hash"] = hw_hash
                self._state["software_hash"] = sw_hash
                self._save_state()
                return True
            else:
                logger.error("inventory.submit failed status=%s", resp.status_code)
        except Exception as e:
            logger.error("inventory.submit error: %s", e)
        return False

    def _hash_hw(self, hw):
        key = f"{hw.get('serial_number', '')}|{hw.get('cpu_model', '')}|{hw.get('ram_total_gb', 0)}"
        return hash(key)

    def _hash_sw(self, sw):
        items = sorted(
            [(s.get("name", ""), s.get("version", "")) for s in sw],
            key=lambda x: x[0],
        )
        return hash(tuple(items))

    def upload_processes(self, client, agent_id, data, logger):
        try:
            resp = client.upload_processes(agent_id, data.get("processes", []), data.get("connections", []))
            if resp and resp.status_code == 200:
                logger.info("processes.uploaded agent=%s procs=%d conns=%d",
                            agent_id, len(data.get("processes", [])), len(data.get("connections", [])))
            else:
                status = resp.status_code if resp else "no_response"
                logger.warning("processes.upload failed agent=%s status=%s", agent_id, status)
        except Exception as e:
            logger.warning("processes.upload error: %s", e)

    def should_submit(self, interval):
        last = self._state.get("last_inventory", 0)
        return (time.time() - last) >= interval

    def report_services(self, client, logger):
        if not self.agent_id:
            return
        try:
            result = self._list_services()
            services = result.get("services", [])
            if services:
                resp = client.report_services(self.agent_id, services)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    logger.info("services.reported count=%d events=%d",
                                data.get("services_count", 0), data.get("events_generated", 0))
                else:
                    status_code = resp.status_code if resp else "no_response"
                    logger.warning("services.report failed status=%s", status_code)
        except Exception as e:
            logger.warning("services.report error: %s", e)

    def _list_services(self):
        import sys as _sys
        if _sys.platform.startswith("win"):
            return {"services": []}
        services = []
        try:
            import subprocess
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all",
                 "--no-pager", "--no-legend", "--plain", "--output=json"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip().startswith("["):
                import json as _json
                units = _json.loads(result.stdout)
                for u in units:
                    svc_name = u.get("unit", "").replace(".service", "")
                    if not svc_name:
                        continue
                    services.append({
                        "name": svc_name,
                        "description": u.get("description", ""),
                        "active_state": u.get("active", ""),
                        "sub_state": u.get("sub", ""),
                    })
        except Exception:
            pass
        return {"services": services}
