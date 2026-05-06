from abc import ABC, abstractmethod


class CollectorBase(ABC):
    def __init__(self, cfg, agent_cfg):
        self.cfg = cfg or {}
        self.agent_cfg = agent_cfg or {}

    @property
    @abstractmethod
    def source_type(self):
        pass

    @abstractmethod
    def collect(self):
        """Return list[dict] normalized events."""
        pass

