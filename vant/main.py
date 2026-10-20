"""
VANT-SIEM Agent — Main Module v2.0.0
Microservices architecture: all requests go through NGINX gateway.
Auth: Register with AUTH service → get token → use for all endpoints.
"""
import argparse
import sys
import time
import threading
import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from vant.config import load_config, find_config
from vant.utils import detect_host, configure_logging, sleep_with_stop, get_current_ips
from vant.api import VantClient
from vant.modules.inventory.service import InventoryService
from vant.modules.heartbeat.service import HeartbeatService
from vant.modules.rules.manager import RuleManager
from vant.modules.rules.base import SigmaRule
from vant.modules.cti.service import CTIService
from vant.modules.compliance.service import ComplianceService

AGENT_VERSION = "2.0.0"

DLP_SCAN_INTERVAL = 30


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

    mon_cfg = cfg.get("monitoring", {})
    if mon_cfg.get("enabled") or mon_cfg.get("processes", {}).get("enabled"):
        try:
            from vant.modules.collectors.system_monitor import SystemMonitorCollector
            collectors.append(SystemMonitorCollector(mon_cfg, agent_cfg))
        except Exception as e:
            logger.warning("system_monitor collector failed: %s", e)
    if mon_cfg.get("services", {}).get("enabled"):
        try:
            from vant.modules.collectors.service_monitor import ServiceMonitorCollector
            collectors.append(ServiceMonitorCollector(mon_cfg, agent_cfg))
        except Exception as e:
            logger.warning("service_monitor collector failed: %s", e)
    if mon_cfg.get("firewall", {}).get("enabled"):
        try:
            from vant.modules.collectors.firewall_monitor import FirewallMonitorCollector
            collectors.append(FirewallMonitorCollector(mon_cfg, agent_cfg))
        except Exception as e:
            logger.warning("firewall_monitor collector failed: %s", e)

    if collectors_cfg.get("fim", {}).get("enabled"):
        try:
            from vant.modules.collectors.fim import FIMCollector
            collectors.append(FIMCollector(collectors_cfg["fim"], agent_cfg))
        except Exception as e:
            logger.warning("fim collector failed to load: %s", e)

    if collectors_cfg.get("vulnscan", {}).get("enabled"):
        try:
            from vant.modules.collectors.vulnscan import VulnscanCollector
            collectors.append(VulnscanCollector(collectors_cfg["vulnscan"], agent_cfg))
        except Exception as e:
            logger.warning("vulnscan collector failed to load: %s", e)

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


def _dlp_scanner_thread(cfg, stop_event, logger):
    try:
        from vant.modules.dlp.aegis import AegisDlpService, _save_state
    except ImportError:
        return
    config_path = cfg.get("_config_path", "")
    dlp_cfg = cfg.get("dlp", cfg.get("aegis_dlp", {}))
    if not dlp_cfg.get("enabled", True):
        return
    try:
        service = AegisDlpService(config_path, cfg)
    except Exception as e:
        logger.warning("dlp.init failed: %s", e)
        return

    server_cfg = cfg.get("server", {})
    dlp_server = dlp_cfg.get("server_url", "")
    if not dlp_server:
        dlp_server = server_cfg.get("url", "https://192.168.12.43")
    token = cfg.get("_auth_token", "") or server_cfg.get("auth_token", "")
    agent_id = cfg.get("agent", {}).get("id", "") or cfg.get("_agent_id", "")

    logger.info("dlp.scanner started interval=%ss server=%s", DLP_SCAN_INTERVAL, dlp_server)

    fetch_cycle = 0
    while not stop_event.is_set():
        try:
            if dlp_server and fetch_cycle % 12 == 0:
                service.fetch_remote_config(dlp_server, token, agent_id)
            fetch_cycle += 1
            incidents = service.scan()
            if incidents:
                logger.info("dlp.scan new_threats=%d", len(incidents))
            pending = service.peek_pending_incidents()
            if pending and dlp_server:
                batch = pending[:50]
                logger.info("dlp.submit sending batch=%d total_pending=%d", len(batch), len(pending))
                try:
                    result = service.submit_threats(dlp_server, token, agent_id, batch)
                    if result is not None:
                        status_code = getattr(result, "status_code", 0)
                        if 200 <= status_code < 300:
                            sent_fps = {inc.get("fingerprint", "") for inc in batch}
                            remaining = [inc for inc in pending if inc.get("fingerprint", "") not in sent_fps]
                            service.state["pending_incidents"] = remaining
                            _save_state(service.state_path, service.state)
                            logger.info("dlp.submitted count=%d status=%d remaining=%d", len(batch), status_code, len(remaining))
                        else:
                            body = getattr(result, "text", "")[:200]
                            logger.warning("dlp.submit rejected status=%d body=%s", status_code, body)
                    else:
                        logger.warning("dlp.submit failed pending=%d", len(pending))
                except Exception as se:
                    logger.warning("dlp.submit exception: %s", se)
        except Exception as e:
            logger.warning("dlp.scan error: %s", e)
        sleep_with_stop(stop_event, DLP_SCAN_INTERVAL)


def _watchdog_thread(stop_event, logger):
    """
    Anti-kill watchdog: monitors the agent process and restarts it if killed.
    In a real implementation, this would be a separate lightweight process.
    """
    logger.info("watchdog.started")
    while not stop_event.is_set():
        # In this mock implementation, we simply log that we are monitoring.
        # To actually implement anti-kill, we would use a companion process
        # or a system service (systemd/windows service) that auto-restarts.
        time.sleep(10)
    logger.info("watchdog.stopped")

def run_with_stop(config_path, stop_event):
    cfg = load_config(config_path)
    cfg["_config_path"] = config_path
    logger = configure_logging(cfg.get("logging", {}), config_path)
    host_name, host_ip = detect_host()

    def _enrich_event_with_cti(event: Dict[str, Any], cti_service: Optional[CTIService]) -> Dict[str, Any]:
        """Enrich event with CTI data if service is available"""
        if not cti_service:
            return event

        # Create a copy of the event to avoid modifying the original
        enriched_event = event.copy()

        # Check for malicious IPs in common fields
        ip_fields = ["src_ip", "dst_ip", "source_ip", "destination_ip", "ip", "ip_address"]
        for field in ip_fields:
            if field in event and isinstance(event[field], str):
                ip = event[field]
                if cti_service.is_ip_malicious(ip):
                    # Add CTI tag to indicate this event involves a malicious IP
                    if "tags" not in enriched_event:
                        enriched_event["tags"] = []
                    if "cti_malicious_ip" not in enriched_event["tags"]:
                        enriched_event["tags"].append("cti_malicious_ip")
                    # Also add the specific malicious IP for context
                    if "cti_malicious_ips" not in enriched_event:
                        enriched_event["cti_malicious_ips"] = []
                    if ip not in enriched_event["cti_malicious_ips"]:
                        enriched_event["cti_malicious_ips"].append(ip)
                    break  # Stop after first malicious IP found (to avoid too many tags)

        # Check for malicious IPs in nested payloads
        raw_payload = event.get("raw_payload", {})
        if isinstance(raw_payload, dict):
            # Check common IP fields in payload
            for field in ip_fields:
                if field in raw_payload and isinstance(raw_payload[field], str):
                    ip = raw_payload[field]
                    if cti_service.is_ip_malicious(ip):
                        if "tags" not in enriched_event:
                            enriched_event["tags"] = []
                        if "cti_malicious_ip" not in enriched_event["tags"]:
                            enriched_event["tags"].append("cti_malicious_ip")
                        if "cti_malicious_ips" not in enriched_event:
                            enriched_event["cti_malicious_ips"] = []
                        if ip not in enriched_event["cti_malicious_ips"]:
                            enriched_event["cti_malicious_ips"].append(ip)
                        break

        return enriched_event

    agent_cfg = cfg.get("agent", {})
    if not agent_cfg.get("host_name"):
        agent_cfg["host_name"] = host_name
    if host_ip and not agent_cfg.get("host_ip"):
        agent_cfg["host_ip"] = host_ip

    client = VantClient(cfg)
    collectors = build_collectors(cfg, logger)

    # Initialize rules manager
    rules_manager = RuleManager()
    rules_config = cfg.get("rules", {})
    rules_dir = rules_config.get("directory")
    if rules_dir:
        # Use custom rules directory if specified in config
        rules_manager = RuleManager(rules_dir)
    else:
        # Use default rules directory
        rules_manager = RuleManager()

    # Load rules from directory
    loaded_count = rules_manager.load_rules_from_directory()
    logger.info(f"Loaded {loaded_count} rules from rules engine")

    interval = int(agent_cfg.get("interval_seconds") or agent_cfg.get("check_interval") or 60)
    log_every = int(agent_cfg.get("log_every_cycles", 60))

    inv_cfg = cfg.get("inventory", {})
    if not inv_cfg:
        inv_cfg = cfg.get("modules", {}).get("inventory", {})
    inv_enabled = inv_cfg.get("enabled", True)
    inv_service = InventoryService(cfg) if inv_enabled else None
    inv_interval = int(inv_cfg.get("interval", 300))

    # Initialize CTI service
    cti_cfg = cfg.get("cti", {})
    cti_enabled = cti_cfg.get("enabled", True)
    cti_service = CTIService(cti_cfg) if cti_enabled else None
    if cti_service:
        cti_service.start()

    # Initialize Compliance service
    compliance_cfg = cfg.get("compliance", {})
    compliance_enabled = compliance_cfg.get("enabled", True)
    compliance_service = ComplianceService(config_path) if compliance_enabled else None
    compliance_interval = int(compliance_cfg.get("interval", 86400))  # default 24 hours
    next_compliance_run = time.time()

    hb_service = HeartbeatService(cfg, logger)
    screen_service = None
    dlp_thread = None
    watchdog_thread = None

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
        cfg.setdefault("agent", {})["id"] = agent_id
        auth_token = inv_service._state.get("auth_token", "")
        if auth_token:
            cfg["_auth_token"] = auth_token
            client.set_token(auth_token)
        logger.info("agent registered id=%s has_token=%s", agent_id, bool(auth_token))
        try:
            from vant.modules.screen.service import ScreenCaptureService
            screen_service = ScreenCaptureService(cfg, client, agent_id, logger)
            logger.info("screen.service initialized")
        except Exception as e:
            logger.warning("screen.service init error=%s", e)

        dlp_cfg = cfg.get("dlp", cfg.get("aegis_dlp", {}))
        if dlp_cfg.get("enabled", True):
            try:
                dlp_thread = threading.Thread(
                    target=_dlp_scanner_thread,
                    args=(cfg, stop_event, logger),
                    daemon=True,
                    name="dlp-scanner",
                )
                dlp_thread.start()
            except Exception as e:
                logger.warning("dlp.thread start error=%s", e)
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
            inv_service.report_services(client, logger)
        except Exception as e:
            logger.warning("startup config check error=%s", e)

        # Start watchdog thread
        watchdog_thread = threading.Thread(
            target=_watchdog_thread,
            args=(stop_event, logger),
            daemon=True,
            name="watchdog"
        )
        watchdog_thread.start()

    exit_reason = None
    cycle = 0
    next_inventory = time.time()
    next_rules_reload = time.time() + rules_config.get("reload_interval", 300)

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

            # Check if it's time to reload rules
            now = time.time()
            if now >= next_rules_reload:
                rules_manager.reload_rules()
                next_rules_reload = now + rules_config.get("reload_interval", 300)
                logger.info("Rules reloaded from directory")

            # Check if it's time to run compliance collection
            if compliance_service and now >= next_compliance_run:
                logger.info("Running compliance evidence collection")
                try:
                    # Collect evidence
                    evidence = compliance_service.collect_evidence(
                        agent_id or "",
                        agent_cfg.get("host_name", ""),
                        agent_cfg.get("host_ip", "")
                    )
                    # Generate a JSON report for HIPAA (we can rotate frameworks in a real implementation)
                    json_report = compliance_service.generate_report(evidence, "HIPAA", "json")
                    # Upload as a log event
                    compliance_event = {
                        "source_type": "compliance_evidence",
                        "source_name": "compliance_service",
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "event_time": datetime.now(timezone.utc).isoformat(),
                        "severity": "info",
                        "event_category": "compliance.report",
                        "message": "Compliance evidence collected",
                        "raw_payload": {
                            "report": json_report,  # Note: This could be large; consider splitting or storing reference
                            "framework": "HIPAA",
                            "timestamp": evidence["collected_at"]
                        },
                        "tags": ["compliance", "report"]
                    }
                    # We'll send the compliance event as a log
                    if compliance_event:
                        client.ingest_logs([compliance_event])
                    # Update next run time
                    next_compliance_run = now + compliance_interval
                    logger.info("Compliance evidence collection completed and uploaded")
                except Exception as e:
                    logger.exception("compliance collection failed: %s", e)
                    # Still update the next run time to avoid tight loop on error
                    next_compliance_run = now + compliance_interval

            # Process events through rules engine
            alert_batch = []
            for event in batch:
                # Enrich event with CTI data
                enriched_event = _enrich_event_with_cti(event, cti_service)
                # Check event against all rules
                matching_rules = rules_manager.match_event(enriched_event)
                if matching_rules:
                    # Create alert event
                    alert_event = {
                        "source_type": "alert",
                        "source_name": "rules_engine",
                        "host_name": agent_cfg.get("host_name", ""),
                        "host_ip": agent_cfg.get("host_ip", ""),
                        "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "severity": "high",  # Could be based on rule level
                        "event_category": "alert.rule_match",
                        "message": f"Rule match: {', '.join([r.title for r in matching_rules])}",
                        "raw_payload": {
                            "original_event": event,
                            "matching_rules": [r.get_info() for r in matching_rules]
                        },
                        "tags": ["alert", "rules_engine"] + [tag for r in matching_rules for tag in r.tags]
                    }

                    # Add CTI information to alert if present in enriched event
                    if "cti_malicious_ips" in enriched_event:
                        alert_event["raw_payload"]["cti_malicious_ips"] = enriched_event["cti_malicious_ips"]
                        if "cti_malicious_ip" not in alert_event["tags"]:
                            alert_event["tags"].append("cti_malicious_ip")
                    alert_batch.append(alert_event)

                    # Log the alert
                    for rule in matching_rules:
                        logger.info(f"RULE MATCH: {rule.rule_id} - {rule.title}")

            # Send original events and alert events
            try:
                if batch:
                    client.ingest_logs(batch)
                if alert_batch:
                    client.ingest_logs(alert_batch)
                if log_every > 0 and (cycle % log_every == 0):
                    logger.info("cycle ok events=%s collectors=%s alerts=%s",
                               len(batch), len(collectors), len(alert_batch))
            except Exception as e:
                logger.error("ingest failed error=%s batch=%s alert_batch=%s", e, len(batch), len(alert_batch))

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
                    inv_service.report_services(client, logger)
                except Exception as e:
                    logger.warning("heartbeat error=%s", e)

            sleep_with_stop(stop_event, interval)

        except Exception as e:
            logger.exception("agent.loop crashed error=%s", e)
            sleep_with_stop(stop_event, 5)

    if screen_service:
        screen_service.stop()
    if cti_service:
        cti_service.shutdown()
    if watchdog_thread:
        # stop_event is already set, but we can explicitly wait or join if not daemon
        pass
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