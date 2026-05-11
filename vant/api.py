import os
import requests


class VantClient:
    def __init__(self, cfg):
        server = cfg.get("server", {})
        control = cfg.get("control", {})
        output = cfg.get("output", {})

        self.base_url = (
            control.get("server_url", server.get("url", "http://localhost:8000"))
            .rstrip("/")
        )

        logs_base = server.get("logs_url", "http://localhost:9201").rstrip("/")
        self.ingest_endpoint = (
            output.get("endpoint") or f"{logs_base}/logs/api/ingest/bulk/"
        )
        self.source_endpoint = (
            output.get("source_endpoint") or f"{logs_base}/logs/api/sources/"
        )

        auth = output.get("auth", {}) or {}
        self.auth_mode = auth.get("mode", server.get("auth_mode", "none"))
        self.token = auth.get("token", server.get("auth_token", ""))
        self.username = auth.get("username", server.get("auth_username", ""))
        self.password = auth.get("password", server.get("auth_password", ""))

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

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.auth_mode == "token" and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _auth(self):
        if self.auth_mode == "basic":
            return (self.username, self.password)
        return None

    def _post(self, url, payload, timeout=None):
        return requests.post(
            url, json=payload, headers=self._headers(),
            auth=self._auth(), timeout=timeout or self.timeout,
            verify=self.verify,
        )

    def _get(self, url, timeout=None):
        return requests.get(
            url, headers=self._headers(),
            auth=self._auth(), timeout=timeout or self.timeout,
            verify=self.verify,
        )

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
        resp = self._post(self.ingest_endpoint, {"events": events}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def upsert_source(self, source):
        return self._post(self.source_endpoint, source)
