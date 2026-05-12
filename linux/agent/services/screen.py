import base64
import io
import logging
import subprocess
import threading
import time


class ScreenCaptureService:
    def __init__(self, output_client, control_server, control_token, agent_id, logger=None):
        self.client = output_client
        self.control_server = control_server
        self.control_token = control_token
        self.agent_id = agent_id
        self.logger = logger or logging.getLogger("vant-siem-agent")
        self._thread = None
        self._stop = threading.Event()
        self._interval = 1.0

    def start(self):
        if self._thread and self._thread.is_alive():
            self.logger.info("screen.service already running")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger.info("screen.service started")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("screen.service stopped")

    def _run(self):
        while not self._stop.is_set():
            try:
                image_b64 = self._capture()
                if image_b64:
                    self._upload(image_b64)
            except Exception as e:
                self.logger.error("screen.capture error=%s", e)
            self._sleep_with_stop(self._interval)

    def _capture(self):
        try:
            from PIL import ImageGrab
            pil_image = ImageGrab.grab()
        except Exception:
            pil_image = self._capture_fallback()
            if pil_image is None:
                return None

        max_dim = 1280
        w, h = pil_image.size
        if w > max_dim or h > max_dim:
            ratio = max_dim / float(max(w, h))
            nw = int(w * ratio)
            nh = int(h * ratio)
            try:
                from PIL import Image
                pil_image = pil_image.resize((nw, nh), Image.LANCZOS)
            except Exception:
                pil_image = pil_image.resize((nw, nh))

        buf = io.BytesIO()
        pil_image.save(buf, format="JPEG", quality=70)
        image_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        self.logger.info("screen.captured size=%d", len(image_b64))
        return image_b64

    def _capture_fallback(self):
        try:
            result = subprocess.run(
                ["import", "-window", "root", "png:-"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                from PIL import Image
                buf = io.BytesIO(result.stdout)
                return Image.open(buf)
        except Exception:
            pass
        try:
            result = subprocess.run(
                ["gnome-screenshot", "-f", "-"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                from PIL import Image
                buf = io.BytesIO(result.stdout)
                return Image.open(buf)
        except Exception:
            pass
        return None

    def _upload(self, image_b64):
        payload = {"agent_id": self.agent_id, "image": image_b64}
        try:
            import requests
            headers = {"Content-Type": "application/json"}
            if self.control_token:
                headers["Authorization"] = f"Bearer {self.control_token}"
            resp = requests.post(
                f"{self.control_server}/inventory/api/screen/upload/",
                json=payload,
                headers=headers,
                timeout=30,
                verify=False,
            )
            if resp.status_code in (200, 201):
                self.logger.info("screen.uploaded status=%s", resp.status_code)
            else:
                self.logger.warning("screen.upload failed status=%s", resp.status_code)
        except Exception as e:
            self.logger.error("screen.upload error=%s", e)

    def _sleep_with_stop(self, seconds):
        remaining = max(0, int(seconds))
        while remaining > 0:
            if self._stop.is_set():
                return
            time.sleep(1)
            remaining -= 1
