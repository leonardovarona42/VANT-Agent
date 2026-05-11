import base64
import io
import threading
import time

from PIL import Image, ImageGrab


class ScreenCaptureService:
    def __init__(self, config, client, agent_id, logger):
        self.config = config
        self.client = client
        self.agent_id = agent_id
        self.logger = logger
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        screen_cfg = config.get("screen", {})
        self.interval = int(screen_cfg.get("capture_interval", 1))
        self.quality = int(screen_cfg.get("jpeg_quality", 50))
        self.max_dim = int(screen_cfg.get("max_dimension", 1280))

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        self.logger.info("screen.capture started interval=%s", self.interval)

    def stop(self):
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("screen.capture stopped")

    @property
    def is_active(self):
        return self._running

    def _capture_loop(self):
        while not self._stop_event.is_set():
            try:
                self._capture_and_upload()
            except Exception as e:
                self.logger.error("screen.capture error=%s", e)
            for _ in range(self.interval):
                if self._stop_event.is_set():
                    return
                time.sleep(1)

    def _capture_and_upload(self):
        try:
            img = ImageGrab.grab()
        except Exception as e:
            self.logger.error("screen.grab failed: %s", e)
            return
        w, h = img.size
        if w > self.max_dim:
            ratio = self.max_dim / w
            img = img.resize((int(w * ratio), int(h * ratio)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=self.quality, optimize=True)
        b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        self.logger.info("screen.captured size=%dx%d jpeg=%dkb", img.size[0], img.size[1], len(b64) * 3 // 4 // 1024)
        try:
            resp = self.client.upload_screenshot(self.agent_id, b64)
            self.logger.info("screen.uploaded status=%s", resp.status_code)
        except Exception as e:
            self.logger.error("screen.upload failed: %s", e)
