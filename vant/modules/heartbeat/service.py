import json
import subprocess
import sys
import time


class HeartbeatService:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.interval = config.get("agent", {}).get("heartbeat_interval", 300)

    def process_commands(self, heartbeat_data, inventory_service, client, logger, config_path, app_logger, screen_service=None):
        if not heartbeat_data:
            return
        commands = heartbeat_data.get("commands", [])
        reloaded = False
        for cmd in commands:
            cmd_type = cmd.get("command_type", "")
            cmd_id = cmd.get("command_id", "")
            payload = cmd.get("payload", {})

            logger.info("command.received type=%s id=%s", cmd_type, cmd_id)

            if cmd_type == "push_config":
                config_data = payload.get("config", {})
                if config_data:
                    self._apply_config(config_data, config_path, logger)
                    client.send_command_result(cmd_id, "completed", {"status": "applied"})
                    reloaded = True
                else:
                    client.send_command_result(cmd_id, "failed", {"error": "empty_config"})
            elif cmd_type == "list_services":
                try:
                    result = self._list_services()
                    resp = client.send_command_result(cmd_id, "completed", result)
                    logger.info("command.completed type=list_services id=%s services=%d", cmd_id, len(result.get("services", [])))
                except Exception as e:
                    logger.error("command.failed type=list_services id=%s error=%s", cmd_id, e)
                    try:
                        client.send_command_result(cmd_id, "failed", {"error": str(e)})
                    except Exception:
                        pass
            elif cmd_type == "list_apt_updates":
                try:
                    result = self._list_apt_updates()
                    client.send_command_result(cmd_id, "completed", result)
                    logger.info("command.completed type=list_apt_updates id=%s packages=%d", cmd_id, len(result.get("packages", [])))
                except Exception as e:
                    logger.error("command.failed type=list_apt_updates id=%s error=%s", cmd_id, e)
                    try:
                        client.send_command_result(cmd_id, "failed", {"error": str(e)})
                    except Exception:
                        pass
            elif cmd_type == "update_inventory":
                if inventory_service:
                    inventory_service.collect_and_submit(client, logger)
                    client.send_command_result(cmd_id, "completed", {"status": "ok"})
            elif cmd_type == "restart_agent":
                logger.warning("command.restart received")
                client.send_command_result(cmd_id, "completed")
                return "restart"
            elif cmd_type == "stop_agent":
                logger.warning("command.stop received")
                client.send_command_result(cmd_id, "completed")
                return "stop"
            elif cmd_type == "start_screen_share":
                logger.info("command.start_screen_share received")
                if screen_service:
                    screen_service.start()
                    client.send_command_result(cmd_id, "completed", {"status": "screen_sharing_started"})
                else:
                    client.send_command_result(cmd_id, "failed", {"error": "screen_service_unavailable"})
            elif cmd_type == "stop_screen_share":
                logger.info("command.stop_screen_share received")
                if screen_service:
                    screen_service.stop()
                    client.send_command_result(cmd_id, "completed", {"status": "screen_sharing_stopped"})
                else:
                    client.send_command_result(cmd_id, "failed", {"error": "screen_service_unavailable"})
            elif cmd_type == "update_agent":
                logger.info("command.update_agent received")
                client.send_command_result(cmd_id, "completed", {"status": "not_implemented"})
            elif cmd_type == "run_script":
                logger.info("command.run_script received")
                client.send_command_result(cmd_id, "completed", {"status": "not_implemented"})
            elif cmd_type == "collect_logs":
                logger.info("command.collect_logs received")
                client.send_command_result(cmd_id, "completed", {"status": "not_implemented"})
            else:
                client.send_command_result(cmd_id, "completed", {"status": f"unknown_command:{cmd_type}"})

        return "reload" if reloaded else None

    def _apply_config(self, config_data, config_path, logger):
        from vant.config import save_config

        updates = {}
        for section in ["inventory", "collectors", "dlp", "agent", "monitoring"]:
            if section in config_data:
                updates[section] = config_data[section]

        if "server" in config_data:
            updates["server"] = config_data["server"]

        if updates:
            try:
                save_config(config_path, updates)
                logger.info("config.applied sections=%s", list(updates.keys()))
            except Exception as e:
                logger.error("config.apply error=%s", e)

    def _list_services(self):
        if sys.platform.startswith("win"):
            return self._list_services_windows()
        return self._list_services_linux()

    def _list_services_linux(self):
        services = []
        try:
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
                        "load_state": u.get("load", ""),
                        "active_state": u.get("active", ""),
                        "sub_state": u.get("sub", ""),
                        "uptime": "",
                        "apt_update": False,
                    })
            else:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split(None, 4)
                    if len(parts) >= 4:
                        svc_name = parts[0].replace(".service", "")
                        services.append({
                            "name": svc_name,
                            "description": parts[4].strip() if len(parts) > 4 else "",
                            "load_state": parts[1],
                            "active_state": parts[2],
                            "sub_state": parts[3],
                            "uptime": "",
                            "apt_update": False,
                        })
        except Exception:
            pass

        try:
            apt_updates = self._list_apt_updates()
            packages = apt_updates.get("packages", [])
        except Exception:
            packages = []

        apt_pkg_names = {u.get("package", "") for u in packages}
        for svc in services:
            svc["apt_update"] = svc["name"] in apt_pkg_names

        return {"services": services, "apt_updates": packages}

    def _list_services_windows(self):
        services = []
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for svc in data:
                    services.append({
                        "name": svc.get("Name", ""),
                        "description": svc.get("DisplayName", ""),
                        "active_state": svc.get("Status", "Unknown").lower(),
                        "sub_state": svc.get("StartType", "Unknown"),
                        "load_state": "loaded",
                        "uptime": "",
                        "apt_update": False,
                    })
        except Exception:
            pass
        return {"services": services, "apt_updates": []}

    def _list_apt_updates(self):
        if sys.platform.startswith("win"):
            return {"packages": []}
        packages = []
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n")[1:]:
                    if "/" in line:
                        pkg_name = line.split("/")[0]
                        parts = line.split()
                        if len(parts) >= 2:
                            current = parts[1] if "[" in parts[1] else ""
                            available = parts[-1].replace("]", "")
                        else:
                            current = ""
                            available = ""
                        packages.append({
                            "package": pkg_name,
                            "current": current,
                            "available": available,
                        })
        except Exception:
            pass
        return {"packages": packages}
