"""
VANT-SIEM Agent — API Client v2.0
Microservices architecture: all requests go through NGINX gateway.
Auth: Register with AUTH service → get token → use for all endpoints.
"""
import logging
import os
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("vant-agent.api")


class VantClient:
    def __init__(self, cfg):
        server = cfg.get("server", {})
        control = cfg.get("control", {})
        output = cfg.get("output", {})

        self.base_url = (
            control.get("server_url") or server.get("url") or "https://localhost"
        ).rstrip("/")

        self.timeout = int(
            output.get("timeout_seconds")
            or control.get("timeout")
            or server.get("timeout", 15)
        )

        tls = output.get("tls", server.get("tls", {})) or {}
        self.verify = tls.get("verify", True)
        ca = tls.get("ca_cert", "")
        if ca and os.path.isfile(ca):
            self.verify = ca

        self.token = cfg.get("_auth_token", "") or server.get("auth_token", "")

        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def set_token(self, token):
        self.token = token

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _post(self, url, payload, timeout=None):
        try:
            return self._session.post(
                url, json=payload, headers=self._headers(),
                timeout=timeout or self.timeout, verify=self.verify,
            )
        except requests.exceptions.ConnectionError:
            logger.warning("connection_failed url=%s", url)
            raise
        except requests.exceptions.Timeout:
            logger.warning("timeout url=%s", url)
            raise

    def _get(self, url, timeout=None):
        try:
            return self._session.get(
                url, headers=self._headers(),
                timeout=timeout or self.timeout, verify=self.verify,
            )
        except requests.exceptions.ConnectionError:
            logger.warning("connection_failed url=%s", url)
            raise
        except requests.exceptions.Timeout:
            logger.warning("timeout url=%s", url)
            raise

    def register_with_auth(self, data):
        return self._post(f"{self.base_url}/auth/api/agent/register/", data)

    def register_agent(self, data):
        return self._post(f"{self.base_url}/inventory/api/register/", data)

    def send_heartbeat(self, agent_id, ip_address=None, config_version=0):
        payload = {"agent_id": agent_id, "config_version": config_version}
        if ip_address:
            payload["ip_address"] = ip_address
        return self._post(f"{self.base_url}/inventory/api/heartbeat/", payload)

    def submit_inventory(self, agent_id, hardware, software=None):
        payload = {
            "agent_id": agent_id,
            "hardware": hardware,
            "software": software or [],
        }
        return self._post(f"{self.base_url}/inventory/api/inventory/submit/", payload, timeout=60)

    def send_command_result(self, command_id, status, result=None, error=""):
        payload = {
            "command_id": command_id,
            "status": status,
            "result": result or {},
            "error": error,
        }
        return self._post(f"{self.base_url}/inventory/api/command-result/", payload)

    def ingest_logs(self, events):
        if not events:
            return {"ok": True, "inserted": 0}
        resp = self._post(f"{self.base_url}/logs/api/ingest/bulk/", {"events": events}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def upsert_source(self, source):
        return self._post(f"{self.base_url}/logs/api/sources/", source)

    def upload_screenshot(self, agent_id, image_b64):
        payload = {"agent_id": str(agent_id), "image": image_b64}
        return self._post(f"{self.base_url}/inventory/api/screen/upload/", payload, timeout=30)

    def fetch_dlp_config(self, token, agent_id):
        return self._get(f"{self.base_url}/aegis/api/agent/dlp/config/", timeout=10)

    def submit_dlp_threats(self, token, agent_id, incidents):
        return self._post(
            f"{self.base_url}/aegis/api/agent/dlp/threats/",
            {"agent_id": agent_id, "incidents": incidents},
            timeout=120,
        )
