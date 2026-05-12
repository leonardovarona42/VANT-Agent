import argparse
import importlib
import os
import sys
import threading
import time
from pathlib import Path

import requests
from PyQt6 import QtCore, QtGui, QtWidgets

_HERE = Path(__file__).resolve().parent


def _load_run_with_stop():
    search_roots = []
    if getattr(sys, "frozen", False):
        meipass = Path(getattr(sys, "_MEIPASS", ""))
        if meipass:
            search_roots.append(meipass)
    search_roots.extend([_HERE, _HERE.parent, Path(sys.executable).resolve().parent])

    for root in search_roots:
        if not root:
            continue
        root_str = str(root)
        if root_str not in sys.path:
            sys.path.insert(0, root_str)
        try:
            module = importlib.import_module("agent")
            return module.run_with_stop
        except ModuleNotFoundError as exc:
            if exc.name != "agent":
                raise
        except Exception:
            continue

    raise ModuleNotFoundError("No module named 'agent'")


run_with_stop = _load_run_with_stop()

_CANDIDATES = [
    _HERE / "staticfiles" / "img" / "logo.png",
    _HERE.parent / "staticfiles" / "img" / "logo.png",
]
LOGO_PATH = next((p for p in _CANDIDATES if p.exists()), _CANDIDATES[0])


def load_cfg(path):
    import yaml

    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def _build_tray_icon():
    for candidate in _CANDIDATES:
        if candidate.exists():
            icon = QtGui.QIcon(str(candidate))
            if not icon.isNull():
                return icon
    app = QtWidgets.QApplication.instance()
    if app is not None:
        return app.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_ComputerIcon)
    return QtGui.QIcon()


class StopDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirmar detencion del agente")
        self.setModal(True)

        layout = QtWidgets.QFormLayout()
        self.username = QtWidgets.QLineEdit()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        layout.addRow("Usuario superusuario:", self.username)
        layout.addRow("Password:", self.password)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        wrapper = QtWidgets.QVBoxLayout()
        wrapper.addLayout(layout)
        wrapper.addWidget(buttons)
        self.setLayout(wrapper)

    def get_credentials(self):
        return self.username.text().strip(), self.password.text()


class AgentTray(QtWidgets.QSystemTrayIcon):
    def __init__(self, config_path, monitor_only=False):
        super().__init__()
        self.config_path = config_path
        self.cfg = load_cfg(config_path)
        self.stop_event = threading.Event()
        self.monitor_only = monitor_only
        self.tray_available = QtWidgets.QSystemTrayIcon.isSystemTrayAvailable()

        icon = _build_tray_icon()
        self.setIcon(icon)
        self.setToolTip("VANT-SIEM Agent v1.01")

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

        if not self.monitor_only and self._can_start_worker():
            self.worker = threading.Thread(
                target=run_with_stop, args=(config_path, self.stop_event), daemon=True
            )
            self.worker.start()
        else:
            self.worker = None

        self.setVisible(True)
        QtWidgets.QApplication.instance().setQuitOnLastWindowClosed(False)
        if self.tray_available and not icon.isNull():
            self.showMessage(
                "VANT-SIEM Agent",
                "Agente listo en la bandeja del sistema.",
                icon,
                2500,
            )
        elif not self.tray_available:
            QtWidgets.QMessageBox.warning(
                None,
                "VANT-SIEM Agent",
                "La bandeja del sistema no esta disponible en esta sesion. "
                "El agente seguira ejecutandose, pero no se mostrara icono.",
            )

    def _show_status(self):
        QtWidgets.QMessageBox.information(
            None, "VANT-SIEM Agent", "El agente esta ejecutandose."
        )

    def _exit_app(self):
        if self.monitor_only or self._authorize_stop():
            self._stop_worker()
            QtWidgets.QApplication.quit()

    def _restart_agent(self):
        if self.monitor_only:
            QtWidgets.QMessageBox.information(
                None,
                "VANT-SIEM Agent",
                "El tray esta en modo monitor-only. Reinicia el agente desde el servicio de Windows.",
            )
            return
        if self._authorize_stop():
            self._stop_worker()
            time.sleep(1)
            self.worker = threading.Thread(
                target=run_with_stop, args=(self.config_path, self.stop_event), daemon=True
            )
            self.stop_event.clear()
            self.worker.start()
            QtWidgets.QMessageBox.information(
                None, "VANT-SIEM Agent", "Agente reiniciado correctamente."
            )

    def _stop_agent(self):
        if self.monitor_only:
            QtWidgets.QMessageBox.information(
                None,
                "VANT-SIEM Agent",
                "El tray esta en modo monitor-only. Deten el servicio de Windows para parar el agente.",
            )
            return
        if self._authorize_stop():
            self._stop_worker()
            QtWidgets.QMessageBox.information(
                None, "VANT-SIEM Agent", "Agente detenido correctamente."
            )

    def _stop_worker(self):
        if self.worker is None:
            return
        self.stop_event.set()
        time.sleep(0.5)

    def _authorize_stop(self):
        control_cfg = self.cfg.get("control", {})
        server_url = (control_cfg.get("server_url") or "").rstrip("/")
        require_https = bool(control_cfg.get("require_https", True))

        if not server_url:
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", "Servidor de control no configurado."
            )
            return False

        if require_https and not server_url.lower().startswith("https://"):
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", "HTTPS requerido para detener el agente."
            )
            return False

        dialog = StopDialog()
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return False

        username, password = dialog.get_credentials()
        payload = {"username": username, "password": password}
        try:
            response = requests.post(
                f"{server_url}/api/agent/authorize-stop/",
                json=payload,
                timeout=8,
            )
            data = response.json()
        except Exception as exc:
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", f"Error de conexion: {exc}"
            )
            return False

        if response.status_code != 200 or not data.get("ok"):
            QtWidgets.QMessageBox.warning(
                None, "VANT-SIEM Agent", "Credenciales invalidas."
            )
            return False

        return True

    def _can_start_worker(self):
        agent_cfg = self.cfg.get("agent", {})
        log_file = (agent_cfg.get("log_file") or "").strip()
        if not log_file:
            return True
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8"):
                pass
            return True
        except Exception:
            QtWidgets.QMessageBox.warning(
                None,
                "VANT-SIEM Agent",
                "No hay permisos para escribir el log del agente. "
                "El tray se iniciara sin ejecutar el agente.",
            )
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="opensearch_agents/config.yaml")
    parser.add_argument("--monitor-only", action="store_true")
    args = parser.parse_args()

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("VANT-SIEM Agent")
    app.setQuitOnLastWindowClosed(False)
    tray = AgentTray(args.config, monitor_only=args.monitor_only)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
