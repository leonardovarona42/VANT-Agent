import time
import requests


class OutputClient:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.endpoint = self.cfg.get("endpoint")
        self.source_endpoint = self.cfg.get("source_endpoint")
        self.timeout = int(self.cfg.get("timeout_seconds", 10))
        self._retry_count = 0

        auth = self.cfg.get("auth", {})
        self.auth_mode = auth.get("mode", "none")
        self.username = auth.get("username", "")
        self.password = auth.get("password", "")
        self.token = auth.get("token", "")

        tls = self.cfg.get("tls", {})
        self.verify = bool(tls.get("verify", True))
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

    def _request_with_retry(self, method, url, **kwargs):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = requests.request(method, url, **kwargs)
                resp.raise_for_status()
                self._retry_count = 0
                return resp
            except (requests.ConnectionError, requests.Timeout) as exc:
                if attempt < max_retries - 1:
                    delay = (2 ** attempt) * min(self.timeout, 5)
                    time.sleep(delay)
                    continue
                raise
        return None

    def upsert_source(self, source):
        if not self.source_endpoint:
            return
        try:
            self._request_with_retry(
                "POST",
                self.source_endpoint,
                json=source,
                headers=self._headers(),
                auth=self._auth(),
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception:
            pass

    def send_events(self, events):
        if not events:
            return {"ok": True, "inserted": 0}
        max_payload_size = 1024 * 1024
        payload = {"events": events}
        payload_bytes = len(str(payload))
        if payload_bytes > max_payload_size:
            events = events[:max(1, len(events) * max_payload_size // payload_bytes)]
            payload = {"events": events}
        try:
            resp = self._request_with_retry(
                "POST",
                self.endpoint,
                json=payload,
                headers=self._headers(),
                auth=self._auth(),
                timeout=self.timeout,
                verify=self.verify,
            )
            if resp is not None:
                return resp.json()
        except Exception:
            pass
        return {"ok": False, "inserted": 0}

