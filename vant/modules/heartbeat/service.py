import json
import time


class HeartbeatService:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.interval = config.get("agent", {}).get("heartbeat_interval", 300)

    def process_commands(self, heartbeat_data, inventory_service, client, logger, config_path, app_logger):
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
            elif cmd_type == "update_inventory":
                if inventory_service:
                    inventory_service.collect_and_submit(client, logger)
                    client.send_command_result(cmd_id, "completed", {"status": "ok"})
            elif cmd_type == "restart_agent":
                logger.warning("command.restart received")
                client.send_command_result(cmd_id, "completed")
                raise SystemExit("Restart requested by server")
            elif cmd_type == "stop_agent":
                logger.warning("command.stop received")
                client.send_command_result(cmd_id, "completed")
                return "stop"
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
        for section in ["inventory", "collectors", "dlp", "agent"]:
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
