"""
CTI Service for downloading and processing threat intelligence feeds
"""
import threading
import time
import json
import logging
import requests
from pathlib import Path
from typing import Dict, Set, List, Optional
from vant.utils import sleep_with_stop

logger = logging.getLogger("vant-cti")


class CTIService:
    """Service for managing Cyber Threat Intelligence feeds"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.update_interval = self.config.get("update_interval", 3600)  # 1 hour default
        self.data_dir = Path(self.config.get("data_dir", "./cti_data"))
        self.data_dir.mkdir(exist_ok=True)

        # Threat intelligence stores
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.malicious_urls: Set[str] = set()
        self.malicious_file_hashes: Dict[str, Set[str]] = {
            "md5": set(),
            "sha1": set(),
            "sha256": set()
        }

        # Feed configurations
        self.feeds = {
            "alienvault_otx": {
                "enabled": self.config.get("alienvault_otx", {}).get("enabled", True),
                "url": "https://otx.alienvault.com/api/v1/indicators/IPv4",
                "parser": self._parse_alienvault_otx_ipv4,
                "update_interval": self.config.get("alienvault_otx", {}).get("update_interval", 3600)
            },
            "abuse_ch_sslbl": {
                "enabled": self.config.get("abuse_ch", {}).get("sslbl", {}).get("enabled", True),
                "url": "https://sslbl.abuse.ch/export/sslbl/ipv4.csv",
                "parser": self._parse_abuse_ch_sslbl,
                "update_interval": self.config.get("abuse_ch", {}).get("sslbl", {}).get("update_interval", 7200)  # 2 hours
            },
            "abuse_ch_fb": {
                "enabled": self.config.get("abuse_ch", {}).get("feodotracker", {}).get("enabled", True),
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                "parser": self._parse_abuse_ch_fb,
                "update_interval": self.config.get("abuse_ch", {}).get("feodotracker", {}).get("update_interval", 3600)
            }
        }

        # Control
        self.stop_event = threading.Event()
        self.update_thread = None
        self.last_update = 0

        # Load existing data
        self._load_stored_data()

        logger.info("CTI Service initialized")

    def start(self):
        """Start the CTI update thread"""
        if not self.enabled:
            logger.info("CTI Service is disabled")
            return

        if self.update_thread is None or not self.update_thread.is_alive():
            self.stop_event.clear()
            self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
            self.update_thread.start()
            logger.info("CTI Service started")

    def stop(self):
        """Stop the CTI update thread"""
        self.stop_event.set()
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=5)
        logger.info("CTI Service stopped")

    def _update_loop(self):
        """Main update loop for CTI feeds"""
        logger.info("CTI update loop started")

        while not self.stop_event.is_set():
            try:
                self._update_all_feeds()
                self.last_update = time.time()

                # Sleep until next update or stop signal
                sleep_with_stop(self.stop_event, self.update_interval)
            except Exception as e:
                logger.error(f"Error in CTI update loop: {e}")
                sleep_with_stop(self.stop_event, 60)  # Sleep 1 minute on error

        logger.info("CTI update loop stopped")

    def _update_all_feeds(self):
        """Update all enabled CTI feeds"""
        logger.info("Updating CTI feeds")

        for feed_name, feed_config in self.feeds.items():
            if not feed_config["enabled"]:
                continue

            try:
                self._update_feed(feed_name, feed_config)
                logger.info(f"Updated CTI feed: {feed_name}")
            except Exception as e:
                logger.error(f"Failed to update CTI feed {feed_name}: {e}")

    def _update_feed(self, feed_name: str, feed_config: Dict):
        """Update a specific CTI feed"""
        # Check if it's time to update this feed
        last_feed_update = self._get_last_feed_update(feed_name)
        if time.time() - last_feed_update < feed_config["update_interval"]:
            return  # Skip if not time yet

        # Download feed data
        try:
            response = requests.get(feed_config["url"], timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f"Failed to download CTI feed {feed_name}: {e}")
            return

        # Parse and store indicators
        new_indicators = feed_config["parser"](response.text)
        self._store_indicators(feed_name, new_indicators)

        # Update last update time
        self._set_last_feed_update(feed_name, time.time())

    def _parse_alienvault_otx_ipv4(self, data: str) -> Dict[str, List[str]]:
        """Parse AlienVault OTX IPv4 feed"""
        indicators = {"ips": []}
        try:
            # AlienVault OTX API returns JSON
            otx_data = json.loads(data)
            if "results" in otx_data:
                for item in otx_data["results"]:
                    if "indicator" in item:
                        indicators["ips"].append(item["indicator"])
        except json.JSONDecodeError:
            logger.warning("Failed to parse AlienVault OTX JSON response")
        return indicators

    def _parse_abuse_ch_sslbl(self, data: str) -> Dict[str, List[str]]:
        """Parse Abuse.ch SSLBL IP feed"""
        indicators = {"ips": []}
        try:
            lines = data.strip().split('\n')
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.split(',')
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    if self._is_valid_ip(ip):
                        indicators["ips"].append(ip)
        except Exception as e:
            logger.warning(f"Failed to parse Abuse.ch SSLBL feed: {e}")
        return indicators

    def _parse_abuse_ch_fb(self, data: str) -> Dict[str, List[str]]:
        """Parse Abuse.ch Feodo Tracker IP blocklist"""
        indicators = {"ips": []}
        try:
            lines = data.strip().split('\n')
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                # Format: IPaddress
                ip = line.strip()
                if self._is_valid_ip(ip):
                    indicators["ips"].append(ip)
        except Exception as e:
            logger.warning(f"Failed to parse Abuse.ch Feodo Tracker feed: {e}")
        return indicators

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True

    def _store_indicators(self, feed_name: str, indicators: Dict[str, List[str]]):
        """Store indicators from a feed"""
        if "ips" in indicators:
            self.malicious_ips.update(indicators["ips"])
            logger.debug(f"Added {len(indicators['ips'])} IPs from {feed_name}")

        # TODO: Add parsing for domains, URLs, file hashes as needed

    def _get_last_feed_update(self, feed_name: str) -> float:
        """Get last update time for a feed"""
        update_file = self.data_dir / f"{feed_name}_last_update.txt"
        if update_file.exists():
            try:
                return float(update_file.read_text().strip())
            except (ValueError, IOError):
                pass
        return 0

    def _set_last_feed_update(self, feed_name: str, timestamp: float):
        """Set last update time for a feed"""
        update_file = self.data_dir / f"{feed_name}_last_update.txt"
        try:
            update_file.write_text(str(timestamp))
        except IOError as e:
            logger.warning(f"Failed to write last update time for {feed_name}: {e}")

    def _load_stored_data(self):
        """Load previously stored threat intelligence data"""
        # Load malicious IPs
        ips_file = self.data_dir / "malicious_ips.txt"
        if ips_file.exists():
            try:
                with open(ips_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and self._is_valid_ip(ip):
                            self.malicious_ips.add(ip)
                logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs from storage")
            except IOError as e:
                logger.warning(f"Failed to load malicious IPs: {e}")

        # TODO: Load other indicator types

    def _store_data(self):
        """Store threat intelligence data to disk"""
        # Store malicious IPs
        ips_file = self.data_dir / "malicious_ips.txt"
        try:
            with open(ips_file, 'w') as f:
                for ip in sorted(self.malicious_ips):
                    f.write(f"{ip}\n")
            logger.info(f"Stored {len(self.malicious_ips)} malicious IPs to storage")
        except IOError as e:
            logger.warning(f"Failed to store malicious IPs: {e}")

        # TODO: Store other indicator types

    def is_ip_malicious(self, ip: str) -> bool:
        """Check if an IP address is known to be malicious"""
        return ip in self.malicious_ips

    def get_stats(self) -> Dict[str, int]:
        """Get CTI statistics"""
        return {
            "malicious_ips": len(self.malicious_ips),
            "malicious_domains": len(self.malicious_domains),
            "malicious_urls": len(self.malicious_urls),
            "malicious_file_hashes_md5": len(self.malicious_file_hashes["md5"]),
            "malicious_file_hashes_sha1": len(self.malicious_file_hashes["sha1"]),
            "malicious_file_hashes_sha256": len(self.malicious_file_hashes["sha256"])
        }

    def shutdown(self):
        """Shutdown the CTI service and store data"""
        self.stop()
        self._store_data()
        logger.info("CTI Service shut down")