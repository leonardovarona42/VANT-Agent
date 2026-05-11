import argparse
import sys
import time
from pathlib import Path

from vant.config import load_config, find_config
from vant.utils import detect_host, configure_logging, sleep_with_stop, get_current_ips
from vant.api import VantClient
from vant.modules.inventory.service import InventoryService
from vant.modules.heartbeat.service import HeartbeatService

AGENT_VERSION = "1.1.0"


def run_tray_mode(config_path):
    import threading
    try:
        from PyQt6 import QtWidgets, QtGui
    except ImportError:
        print("Error: PyQt6 is required for tray mode. Install with: pip install PyQt6")
        sys.exit(1)

    class _Stop:
        def __init__(self):
            self._event = threading.Event()
        def is_set(self):
            return self._event.is_set()
        def set(self):
            self._event.set()

    class TrayApp(QtWidgets.QSystemTrayIcon):
        def __init__(self, cfg_path):
            super().__init__()
            self.config_path = cfg_path
            self.stop = _Stop()
            icon = QtGui.QIcon()
            cfg_dir = Path(cfg_path).parent
            base = Path(getattr(sys, "_MEIPASS", str(Path(__file__).parent.parent)))
            for candidate in [
                cfg_dir / "logo.png",
                base / "img" / "logo.png",
                base / "staticfiles" / "img" / "logo.png",
            ]:
                if candidate.exists():
                    icon = QtGui.QIcon(str(candidate))
                    if not icon.isNull():
                        break
            self.setIcon(icon)
            self.setToolTip("VANT-SIEM Agent v" + AGENT_VERSION)

            menu = QtWidgets.QMenu()
            menu.addAction("Status", lambda: QtWidgets.QMessageBox.information(None, "VANT Agent", "Agent is running"))
            menu.addAction("Restart", self._restart)
            menu.addAction("Stop", self._stop)
            menu.addAction("Exit", self._exit)
            self.setContextMenu(menu)

            self._start_agent()
            self.setVisible(True)
            QtWidgets.QApplication.instance().setQuitOnLastWindowClosed(False)
            if QtWidgets.QSystemTrayIcon.isSystemTrayAvailable() and not icon.isNull():
                self.showMessage("VANT-SIEM Agent", f"Agent v{AGENT_VERSION} running in system tray", icon, 2500)

        def _start_agent(self):
            self.stop = _Stop()
            self.worker = threading.Thread(target=self._run, args=(self.stop,), daemon=True)
            self.worker.start()

        def _run(self, stop_ev):
            while not stop_ev.is_set():
                reason = run_with_stop(self.config_path, stop_ev)
                if stop_ev.is_set() or reason != "restart":
                    break

        def _restart(self):
            self.stop.set()
            self.worker.join(timeout=15)
            self._start_agent()
            QtWidgets.QMessageBox.information(None, "VANT Agent", "Agent restarted")

        def _stop(self):
            self.stop.set()
            QtWidgets.QMessageBox.information(None, "VANT Agent", "Agent stopped")

        def _exit(self):
            self.stop.set()
            QtWidgets.QApplication.quit()

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("VANT-SIEM Agent")
    app.setQuitOnLastWindowClosed(False)
    _tray = TrayApp(config_path)
    sys.exit(app.exec())


def build_collectors(cfg, logger):
    collectors = []
    collectors_cfg = cfg.get("collectors", {})
    agent_cfg = cfg.get("agent", {})

    _BASE_DIR = str(Path(__file__).resolve().parent.parent)
    if _BASE_DIR not in sys.path:
        sys.path.insert(0, _BASE_DIR)

    if collectors_cfg.get("snort", {}).get("enabled"):
        try:
            from vant.modules.collectors.snort import SnortCollector
            collectors.append(SnortCollector(collectors_cfg["snort"], agent_cfg))
        except Exception as e:
            logger.warning("snort collector failed to load: %s", e)

    if collectors_cfg.get("suricata", {}).get("enabled"):
        try:
            from vant.modules.collectors.suricata import SuricataCollector
            collectors.append(SuricataCollector(collectors_cfg["suricata"], agent_cfg))
        except Exception as e:
            logger.warning("suricata collector failed to load: %s", e)

    if collectors_cfg.get("windows_eventlog", {}).get("enabled"):
        try:
            from vant.modules.collectors.windows_eventlog import WindowsEventLogCollector
            win_cfg = collectors_cfg["windows_eventlog"]
            channels = win_cfg.get("channels", [])
            if isinstance(channels, str):
                channels = [c.strip() for c in channels.split(",") if c.strip()]
            channels = [c for c in channels if "\\" not in c and "/" not in c and not c.endswith("*")]
            if channels:
                for ch in channels:
                    ch_cfg = dict(win_cfg)
                    ch_cfg["channel"] = ch
                    collectors.append(WindowsEventLogCollector(ch_cfg, agent_cfg))
            else:
                collectors.append(WindowsEventLogCollector(win_cfg, agent_cfg))
        except Exception as e:
            logger.warning("windows_eventlog collector failed to load: %s", e)

    if collectors_cfg.get("postgres", {}).get("enabled"):
        try:
            from vant.modules.collectors.postgres_log import PostgresLogCollector
            collectors.append(PostgresLogCollector(collectors_cfg["postgres"], agent_cfg))
        except Exception as e:
            logger.warning("postgres collector failed to load: %s", e)

    if collectors_cfg.get("file_logs", {}).get("enabled"):
        try:
            from vant.modules.collectors.file_log import FileLogCollector
            collectors.append(FileLogCollector(collectors_cfg["file_logs"], agent_cfg))
        except Exception as e:
            logger.warning("file_log collector failed to load: %s", e)

    return collectors


def _ensure_host_fields(event, host_name, host_ip):
    if not event.get("host_name"):
        event["host_name"] = host_name
    raw = event.get("raw_payload")
    if raw is None or not isinstance(raw, dict):
        raw = {}
    if host_name and "host_name" not in raw:
        raw["host_name"] = host_name
    if host_ip and "host_ip" not in raw:
        raw["host_ip"] = host_ip
    event["raw_payload"] = raw
    return event


def run_with_stop(config_path, stop_event):
    cfg = load_config(config_path)
    cfg["_config_path"] = config_path
    logger = configure_logging(cfg.get("logging", {}), config_path)
    host_name, host_ip = detect_host()

    agent_cfg = cfg.get("agent", {})
    if not agent_cfg.get("host_name"):
        agent_cfg["host_name"] = host_name
    if host_ip and not agent_cfg.get("host_ip"):
        agent_cfg["host_ip"] = host_ip

    client = VantClient(cfg)
    collectors = build_collectors(cfg, logger)
    interval = int(agent_cfg.get("interval_seconds") or agent_cfg.get("check_interval") or 60)
    log_every = int(agent_cfg.get("log_every_cycles", 60))

    inv_cfg = cfg.get("inventory", {})
    if not inv_cfg:
        inv_cfg = cfg.get("modules", {}).get("inventory", {})
    inv_enabled = inv_cfg.get("enabled", True)
    inv_service = InventoryService(cfg) if inv_enabled else None
    inv_interval = int(inv_cfg.get("interval", 300))

    hb_service = HeartbeatService(cfg, logger)
    screen_service = None

    logger.info(
        "agent.starting version=%s host=%s ip=%s interval=%ss collectors=%s",
        AGENT_VERSION,
        agent_cfg.get("host_name", ""),
        agent_cfg.get("host_ip", ""),
        interval,
        ",".join([c.source_type for c in collectors]) or "none",
    )

    for c in collectors:
        try:
            client.upsert_source({
                "source_id": f"{agent_cfg.get('id', 'agent')}-{c.source_type}",
                "source_type": c.source_type,
                "host_name": agent_cfg.get("host_name", ""),
                "enabled": True,
                "meta": {
                    "host_name": agent_cfg.get("host_name", ""),
                    "host_ip": agent_cfg.get("host_ip", ""),
                    "agent_version": AGENT_VERSION,
                },
            })
        except Exception as e:
            logger.warning("upsert_source failed: %s", e)

    if inv_service and not inv_service.agent_id:
        logger.info("registering with inventory service...")
        inv_service.register(client, logger)

    if inv_service and inv_service.agent_id:
        agent_id = inv_service.agent_id
        logger.info("agent registered id=%s", agent_id)
        try:
            from vant.modules.screen.service import ScreenCaptureService
            screen_service = ScreenCaptureService(cfg, client, agent_id, logger)
            logger.info("screen.service initialized")
        except Exception as e:
            logger.warning("screen.service init error=%s", e)
        for c in collectors:
            try:
                client.upsert_source({
                    "source_id": str(agent_id),
                    "source_type": c.source_type,
                    "host_name": agent_cfg.get("host_name", ""),
                    "enabled": True,
                    "meta": {
                        "agent_id": str(agent_id),
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "agent_version": AGENT_VERSION,
                        "collector": c.source_type,
                    },
                })
            except Exception as e:
                logger.warning("upsert_source failed: %s", e)

        logger.info("checking for pending config commands...")
        try:
            hb_data = inv_service.heartbeat(client, logger)
            if hb_data:
                result = hb_service.process_commands(hb_data, inv_service, client, logger, config_path, logger, screen_service=screen_service)
                if result == "reload":
                    cfg = load_config(config_path)
                    cfg["_config_path"] = config_path
                    agent_cfg = cfg.get("agent", {})
                    collectors = build_collectors(cfg, logger)
                    interval = int(agent_cfg.get("check_interval") or agent_cfg.get("interval_seconds") or 60)
                    logger.info("config.applied and collectors rebuilt on startup")
                elif result in ("restart", "stop"):
                    logger.info("command.%s at startup, exiting", result)
                    if screen_service:
                        screen_service.stop()
                    logger.info("agent.stopped")
                    return result
        except Exception as e:
            logger.warning("startup config check error=%s", e)

    exit_reason = None
    cycle = 0
    next_inventory = time.time()

    agent_id = inv_service.agent_id if inv_service else None

    while not stop_event.is_set():
        try:
            cycle += 1
            batch = []
            for collector in collectors:
                try:
                    events = collector.collect()
                    for ev in events:
                        _ensure_host_fields(ev, agent_cfg.get("host_name", ""), agent_cfg.get("host_ip", ""))
                        if agent_id:
                            ev["agent_id"] = agent_id
                    batch.extend(events)
                except Exception as e:
                    logger.exception("collector failed source=%s", collector.source_type)

            try:
                if batch:
                    client.ingest_logs(batch)
                if log_every > 0 and (cycle % log_every == 0):
                    logger.info("cycle ok events=%s collectors=%s", len(batch), len(collectors))
            except Exception as e:
                logger.error("ingest failed error=%s batch=%s", e, len(batch))

            now = time.time()

            if inv_service and now >= next_inventory:
                if not inv_service.agent_id:
                    inv_service.register(client, logger)
                if inv_service.agent_id:
                    inv_service.collect_and_submit(client, logger)
                next_inventory = now + inv_interval

            if inv_service and inv_service.agent_id:
                try:
                    hb_data = inv_service.heartbeat(client, logger)
                    if hb_data:
                        result = hb_service.process_commands(hb_data, inv_service, client, logger, config_path, logger, screen_service=screen_service)
                        if result == "reload":
                            cfg = load_config(config_path)
                            cfg["_config_path"] = config_path
                            agent_cfg = cfg.get("agent", {})
                            collectors = build_collectors(cfg, logger)
                            interval = int(agent_cfg.get("interval_seconds") or agent_cfg.get("check_interval") or 60)
                            inv_cfg = cfg.get("inventory", {})
                            if inv_cfg.get("enabled"):
                                inv_interval = int(inv_cfg.get("interval", 300))
                            logger.info("config.applied and collectors rebuilt")
                        elif result in ("restart", "stop"):
                            exit_reason = result
                            if result == "stop":
                                stop_event.set()
                            break
                except Exception as e:
                    logger.warning("heartbeat error=%s", e)

            sleep_with_stop(stop_event, interval)

        except Exception as e:
            logger.exception("agent.loop crashed error=%s", e)
            sleep_with_stop(stop_event, 5)

    if screen_service:
        screen_service.stop()
    logger.info("agent.stopped")
    return exit_reason


def run(config_path):
    import threading
    while True:
        stop_ev = threading.Event()
        reason = run_with_stop(config_path, stop_ev)
        if stop_ev.is_set() or reason != "restart":
            break


def main():
    parser = argparse.ArgumentParser(description="VANT-SIEM Agent")
    parser.add_argument("--config", default=find_config(), help="Path to config.yaml")
    parser.add_argument("--tray", action="store_true", help="Run with system tray icon")
    args = parser.parse_args()

    if not args.config:
        print("Error: No config file found. Create config.yaml or use --config")
        sys.exit(1)

    if args.tray:
        run_tray_mode(args.config)
    else:
        print(f"VANT-SIEM Agent v{AGENT_VERSION}")
        print(f"Config: {args.config}")
        run(args.config)


if __name__ == "__main__":
    main()
