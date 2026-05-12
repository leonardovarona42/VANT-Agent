from abc import ABC, abstractmethod


class CollectorBase(ABC):
    def __init__(self, cfg, agent_cfg):
        self.cfg = cfg or {}
        self.agent_cfg = agent_cfg or {}
        self._host_ip = self._resolve_ip()

    def _resolve_ip(self):
        from vant.utils import detect_host
        _, ip = detect_host()
        return ip

    @property
    @abstractmethod
    def source_type(self):
        pass

    @abstractmethod
    def collect(self):
        """Return list[dict] normalized events."""
        pass

