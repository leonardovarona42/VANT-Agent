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


def build_collectors(cfg, logger):
    collectors = []
    collectors_cfg = cfg.get("collectors", {})
    agent_cfg = cfg.get("agent", {})

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
    interval = int(agent_cfg.get("check_interval", 60))
    log_every = int(agent_cfg.get("log_every_cycles", 60))

    inv_cfg = cfg.get("inventory", {})
    inv_enabled = inv_cfg.get("enabled", True)
    inv_service = InventoryService(cfg) if inv_enabled else None
    inv_interval = int(inv_cfg.get("interval", 86400))

    hb_service = HeartbeatService(cfg, logger)

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

    cycle = 0
    next_inventory = time.time()

    while not stop_event.is_set():
        try:
            cycle += 1
            batch = []
            for collector in collectors:
                try:
                    events = collector.collect()
                    for ev in events:
                        _ensure_host_fields(ev, agent_cfg.get("host_name", ""), agent_cfg.get("host_ip", ""))
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
                    result = hb_service.process_commands(hb_data, inv_service, client, logger)
                    if result == "stop":
                        stop_event.set()
                        break
                except SystemExit:
                    raise
                except Exception as e:
                    logger.warning("heartbeat error=%s", e)

            sleep_with_stop(stop_event, interval)

        except SystemExit:
            break
        except Exception as e:
            logger.exception("agent.loop crashed error=%s", e)
            sleep_with_stop(stop_event, 5)

    logger.info("agent.stopped")


def run(config_path):
    class _Stop:
        def is_set(self):
            return False
        def set(self):
            return None
    run_with_stop(config_path, _Stop())


def main():
    parser = argparse.ArgumentParser(description="VANT-SIEM Agent")
    parser.add_argument("--config", default=find_config(), help="Path to config.yaml")
    args = parser.parse_args()

    if not args.config:
        print("Error: No config file found. Create config.yaml or use --config")
        sys.exit(1)

    print(f"VANT-SIEM Agent v{AGENT_VERSION}")
    print(f"Config: {args.config}")
    run(args.config)


if __name__ == "__main__":
    main()
