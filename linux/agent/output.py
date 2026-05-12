import requests


class OutputClient:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.endpoint = self.cfg.get("endpoint")
        self.source_endpoint = self.cfg.get("source_endpoint")
        self.timeout = int(self.cfg.get("timeout_seconds", 10))

        auth = self.cfg.get("auth", {})
        self.auth_mode = auth.get("mode", "none")
        self.username = auth.get("username", "")
        self.password = auth.get("password", "")
        self.token = auth.get("token", "")

        tls = self.cfg.get("tls", {})
        self.verify = bool(tls.get("verify", False))
        ca_cert = tls.get("ca_cert", "")
        if self.verify and ca_cert:
            self.verify = ca_cert

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.auth_mode == "token" and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _auth(self):
        if self.auth_mode == "basic":
            return (self.username, self.password)
        return None

    def upsert_source(self, source):
        if not self.source_endpoint:
            return
        requests.post(
            self.source_endpoint,
            json=source,
            headers=self._headers(),
            auth=self._auth(),
            timeout=self.timeout,
            verify=self.verify,
        )

    def send_events(self, events):
        if not events:
            return {"ok": True, "inserted": 0}
        resp = requests.post(
            self.endpoint,
            json={"events": events},
            headers=self._headers(),
            auth=self._auth(),
            timeout=self.timeout,
            verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def upload_screenshot(self, agent_id, image_b64):
        payload = {"agent_id": agent_id, "image": image_b64}
        try:
            resp = requests.post(
                f"{self.endpoint.rstrip('/api/')}/inventory/api/screen/upload/",
                json=payload,
                headers=self._headers(),
                auth=self._auth(),
                timeout=30,
                verify=self.verify,
            )
            return resp.status_code in (200, 201)
        except Exception:
            return False

