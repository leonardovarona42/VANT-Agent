from abc import ABC, abstractmethod
import socket


class CollectorBase(ABC):
    def __init__(self, cfg, agent_cfg):
        self.cfg = cfg or {}
        self.agent_cfg = agent_cfg or {}
        self._host_ip = self._resolve_ip()

    def _resolve_ip(self):
        ip = ""
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass
        if ip.startswith("127.") or not ip:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    ip = s.getsockname()[0]
            except Exception:
                pass
        return ip

    @property
    @abstractmethod
    def source_type(self):
        pass

    @abstractmethod
    def collect(self):
        pass
