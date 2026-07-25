from abc import ABC, abstractmethod
import socket


class CollectorBase(ABC):
    def __init__(self, cfg, agent_cfg):
        self.cfg = cfg or {}
        self.agent_cfg = agent_cfg or {}
        self._host_ip = self._resolve_ip()

    def _resolve_ip(self):
        try:
            from vant.utils import detect_host
            _, ip = detect_host()
            return ip
        except ImportError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    @property
    @abstractmethod
    def source_type(self):
        pass

    @abstractmethod
    def collect(self):
        pass

