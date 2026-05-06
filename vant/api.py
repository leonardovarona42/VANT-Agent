import os
import requests


class VantClient:
    def __init__(self, cfg):
        server = cfg.get("server", {})
        self.base_url = server.get("url", "http://localhost:8000").rstrip("/")
        self.logs_url = server.get("logs_url", "http://localhost:9201").rstrip("/")
        auth = server.get("auth", {})
        self.auth_mode = auth.get("mode", "none")
        self.token = auth.get("token", "")
        self.username = auth.get("username", "")
        self.password = auth.get("password", "")
        self.timeout = int(server.get("timeout", 15))

        tls = server.get("tls", {})
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

    # ---- Inventory Service (port 8003) ----

    def register_agent(self, data):
        return self._post(f"{self.base_url}/inventory/api/register/", data)

    def send_heartbeat(self, agent_id, ip_address=None):
        payload = {"agent_id": agent_id}
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

    # ---- Logs Service (port 9201) ----

    def ingest_logs(self, events):
        if not events:
            return {"ok": True, "inserted": 0}
        resp = self._post(f"{self.logs_url}/logs/api/ingest/bulk/", {"events": events}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def upsert_source(self, source):
        return self._post(f"{self.logs_url}/logs/api/sources/", source)
