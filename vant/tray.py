import argparse
import os
import sys
import threading
import time
from pathlib import Path

import yaml
from PyQt6 import QtCore, QtGui, QtWidgets

_HERE = Path(__file__).resolve().parent


def load_cfg(path):
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def _run_agent(config_path, stop_event):
    try:
        from vant.main import run_with_stop
        run_with_stop(config_path, stop_event)
    except ImportError:
        try:
            from agent import run_with_stop as _legacy
            _legacy(config_path, stop_event)
        except ImportError:
            pass


class AgentTray(QtWidgets.QSystemTrayIcon):
    def __init__(self, config_path, monitor_only=False):
        super().__init__()
        self.config_path = config_path
        self.cfg = load_cfg(config_path)
        self.stop_event = threading.Event()
        self.monitor_only = monitor_only
        self.tray_available = QtWidgets.QSystemTrayIcon.isSystemTrayAvailable()

        icon = QtGui.QIcon()
        for candidate in [
            _HERE / "staticfiles" / "img" / "logo.png",
            _HERE.parent / "staticfiles" / "img" / "logo.png",
        ]:
            if candidate.exists():
                icon = QtGui.QIcon(str(candidate))
                if not icon.isNull():
                    break
        self.setIcon(icon)
        self.setToolTip("VANT-SIEM Agent v1.1.0")

        self.menu = QtWidgets.QMenu()
        self.action_show = self.menu.addAction("Mostrar estado")
        self.action_restart = self.menu.addAction("Reiniciar agente")
        self.action_stop = self.menu.addAction("Detener agente")
        self.action_exit = self.menu.addAction("Salir")
        self.setContextMenu(self.menu)

        if self.monitor_only:
            self.action_restart.setEnabled(False)
            self.action_stop.setEnabled(False)

        self.action_show.triggered.connect(self._show_status)
        self.action_restart.triggered.connect(self._restart_agent)
        self.action_stop.triggered.connect(self._stop_agent)
        self.action_exit.triggered.connect(self._exit_app)

        if not self.monitor_only:
            self._start_worker()

        self.setVisible(True)
        QtWidgets.QApplication.instance().setQuitOnLastWindowClosed(False)
        if self.tray_available and not icon.isNull():
            self.showMessage(
                "VANT-SIEM Agent",
                "Agente listo en la bandeja del sistema.",
                icon, 2500,
            )

    def _start_worker(self):
        self.stop_event.clear()
        self.worker = threading.Thread(
            target=_run_agent, args=(self.config_path, self.stop_event), daemon=True
        )
        self.worker.start()

    def _show_status(self):
        QtWidgets.QMessageBox.information(
            None, "VANT-SIEM Agent", "El agente esta ejecutandose."
        )

    def _exit_app(self):
        self._stop_worker()
        QtWidgets.QApplication.quit()

    def _restart_agent(self):
        if self.monitor_only:
            return
        self._stop_worker()
        time.sleep(1)
        self._start_worker()
        QtWidgets.QMessageBox.information(
            None, "VANT-SIEM Agent", "Agente reiniciado correctamente."
        )

    def _stop_agent(self):
        if self.monitor_only:
            return
        self._stop_worker()
        QtWidgets.QMessageBox.information(
            None, "VANT-SIEM Agent", "Agente detenido correctamente."
        )

    def _stop_worker(self):
        self.stop_event.set()
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--monitor-only", action="store_true")
    args = parser.parse_args()

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("VANT-SIEM Agent")
    app.setQuitOnLastWindowClosed(False)
    tray = AgentTray(args.config, monitor_only=args.monitor_only)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
