#!/usr/bin/env python3
"""
VANT-Agent Windows Installer - GUI Wizard
"""
import os
import sys
import socket
import json
import uuid
import time
import shutil
import ctypes
import platform
import subprocess
from pathlib import Path

import requests
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QVBoxLayout, QHBoxLayout,
    QWidget, QLabel, QLineEdit, QPushButton, QProgressBar, QTextEdit,
    QMessageBox, QFileDialog, QGroupBox, QFormLayout,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

_VERSION = "1.1.0"

# Default service URLs
DEFAULT_INVENTORY_URL = "http://localhost:8003"
DEFAULT_LOGS_URL = "http://localhost:9201"


def _map_os_type():
    system = platform.system().lower()
    release = platform.release()

    if system == "windows":
        return "windows", release
    elif system == "linux":
        return "linux", release
    elif system == "darwin":
        return "macos", release

    return "other", release


def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def _get_mac():
    mac = uuid.getnode()
    return ":".join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))


def _get_hostname():
    return platform.node()


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class ConnectionTestThread(QThread):
    result = pyqtSignal(bool, dict)

    def __init__(self, inventory_url, logs_url):
        super().__init__()
        self.inventory_url = inventory_url.rstrip("/")
        self.logs_url = logs_url.rstrip("/")

    def run(self):
        results = {"inventory": (False, ""), "logs": (False, "")}
        all_ok = True

        try:
            r = requests.get(f"{self.inventory_url}/inventory/api/health/", timeout=5)
            if r.status_code == 200:
                data = r.json()
                status = data.get("status", "unknown")
                db = data.get("database", "unknown")
                agents = data.get("total_agents", 0)
                results["inventory"] = (True, f"Inventory: {status} (DB: {db}, Agents: {agents})")
            else:
                all_ok = False
                results["inventory"] = (False, f"HTTP {r.status_code}")
        except Exception as e:
            all_ok = False
            results["inventory"] = (False, f"Connection failed: {e}")

        try:
            r = requests.get(f"{self.logs_url}/logs/api/health/", timeout=5)
            if r.status_code == 200:
                data = r.json()
                status = data.get("status", "unknown")
                db = data.get("database", "unknown")
                results["logs"] = (True, f"Logs: {status} (DB: {db})")
            else:
                all_ok = False
                results["logs"] = (False, f"HTTP {r.status_code}")
        except Exception as e:
            all_ok = False
            results["logs"] = (False, f"Connection failed: {e}")

        self.result.emit(all_ok, results)


class EnrollmentThread(QThread):
    result = pyqtSignal(bool, dict, str)

    def __init__(self, inventory_url, hostname, mac, os_type, os_version, os_arch, ip_address):
        super().__init__()
        self.inventory_url = inventory_url.rstrip("/")
        self.hostname = hostname
        self.mac = mac
        self.os_type = os_type
        self.os_version = os_version
        self.os_arch = os_arch
        self.ip_address = ip_address

    def run(self):
        try:
            payload = {
                "hostname": self.hostname,
                "mac_address": self.mac,
                "os_type": self.os_type,
                "os_version": self.os_version,
                "os_arch": self.os_arch,
                "agent_version": _VERSION,
                "ip_address": self.ip_address,
                "machine_name": self.hostname,
            }
            r = requests.post(
                f"{self.inventory_url}/inventory/api/register/",
                json=payload,
                timeout=10,
            )
            try:
                resp_data = r.json()
            except Exception:
                resp_data = {}

            if r.status_code in (200, 201):
                self.result.emit(True, resp_data, "")
            else:
                errors = resp_data if isinstance(resp_data, dict) else {}
                self.result.emit(False, {}, f"HTTP {r.status_code}: {errors}")
        except Exception as e:
            self.result.emit(False, {}, str(e))


class InstallerThread(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(bool, str)

    def __init__(self, config, install_dir):
        super().__init__()
        self.config = config
        self.install_dir = install_dir

    def run(self):
        try:
            self.progress.emit(5, "Preparing installation directory...")
            os.makedirs(self.install_dir, exist_ok=True)

            self.progress.emit(20, "Copying agent executable...")
            src_exe = None
            candidates = [
                Path(__file__).parent / "VANT-Agent.exe",
                Path(getattr(sys, "_MEIPASS", "")) / "VANT-Agent.exe" if getattr(sys, "_MEIPASS", None) else None,
                Path(sys.executable).parent / "VANT-Agent.exe",
                Path(sys.executable).parent.parent / "dist" / "VANT-Agent.exe",
            ]
            for p in candidates:
                if p and p.exists():
                    src_exe = p
                    break
            if not src_exe:
                self.finished.emit(False, "VANT-Agent.exe not found in installer package.")
                return
            dst_exe = Path(self.install_dir) / "VANT-Agent.exe"
            shutil.copy2(str(src_exe), str(dst_exe))

            logo_candidates = [
                Path(getattr(sys, "_MEIPASS", "")) / "logo.png",
                Path(__file__).parent / "logo.png",
                Path(sys.executable).parent / "logo.png",
            ]
            for lc in logo_candidates:
                if lc and lc.exists():
                    shutil.copy2(str(lc), str(Path(self.install_dir) / "logo.png"))
                    break

            self.progress.emit(45, "Generating configuration...")
            config_data = {
                "agent": {
                    "name": "VANT-SIEM Agent",
                    "version": _VERSION,
                    "log_file": str(Path(self.install_dir) / "logs" / "agent.log"),
                    "log_level": "INFO",
                    "check_interval": 60,
                    "heartbeat_interval": 300,
                    "agent_id": self.config.get("agent_id", ""),
                },
                "server": {
                    "url": self.config["inventory_url"],
                    "logs_url": self.config["logs_url"],
                    "auth": {"mode": "none"},
                    "tls": {"verify": True},
                },
                "inventory": {
                    "enabled": True,
                    "interval": 300,
                },
                "collectors": {
                    "windows_eventlog": {
                        "enabled": True,
                        "channels": ["Application", "Security", "System"],
                    }
                },
            }

            import yaml
            config_path = Path(self.install_dir) / "config.yaml"
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

            self.progress.emit(65, "Creating directories...")
            (Path(self.install_dir) / "logs").mkdir(exist_ok=True)
            (Path(self.install_dir) / ".vant_state").mkdir(exist_ok=True)

            self.progress.emit(80, "Creating desktop shortcut...")
            try:
                desktop = Path(os.environ["USERPROFILE"]) / "Desktop"
                lnk_path = desktop / "VANT-Agent.lnk"
                ps_cmd = (
                    f'$W = New-Object -ComObject WScript.Shell; '
                    f'$S = $W.CreateShortcut("{lnk_path}"); '
                    f'$S.TargetPath = "{dst_exe}"; '
                    f'$S.WorkingDirectory = "{self.install_dir}"; '
                    f'$S.Description = "VANT-SIEM Agent v{_VERSION}"; '
                    f'$S.Save()'
                )
                subprocess.run(
                    ["powershell", "-Command", ps_cmd],
                    capture_output=True, timeout=10,
                )
            except Exception:
                pass

            self.progress.emit(95, "Setting up auto-start...")
            task_name = "VANT-SIEM-Agent"
            try:
                subprocess.run(
                    ["schtasks", "/Delete", "/TN", task_name, "/F"],
                    capture_output=True, timeout=10,
                )
            except Exception:
                pass

            schtask_cmd = (
                f'schtasks /Create /TN "{task_name}" '
                f'/TR "\\"{dst_exe}\\" --tray --config \\"{config_path}\\"" '
                f"/SC ONLOGON /RL HIGHEST /F"
            )
            subprocess.run(schtask_cmd, shell=True, capture_output=True, timeout=30)

            self.progress.emit(98, "Launching agent...")
            try:
                subprocess.Popen(
                    [str(dst_exe), "--tray", "--config", str(config_path)],
                    cwd=self.install_dir,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                )
            except Exception:
                pass

            time.sleep(0.5)
            self.progress.emit(100, "Installation complete!")
            self.finished.emit(True, "Installation completed successfully! Agent is now running.")

        except Exception as e:
            self.finished.emit(False, f"Installation failed: {e}")


class WizardPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(40, 30, 40, 30)


class WelcomePage(WizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)

        title = QLabel("VANT-SIEM Agent")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #1a73e8;")
        self.layout.addWidget(title)

        subtitle = QLabel(f"Installer v{_VERSION}")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #5f6368;")
        self.layout.addWidget(subtitle)

        self.layout.addSpacing(30)

        info = QLabel(
            "This wizard will guide you through:\n\n"
            "  1. Configure VANT-SIEM service connection\n"
            "  2. Test connectivity to Inventory and Logs services\n"
            "  3. Enroll this machine with the server\n"
            "  4. Install the agent to your system\n"
        )
        info.setFont(QFont("Segoe UI", 11))
        info.setWordWrap(True)
        info.setStyleSheet("color: #3c4043;")
        self.layout.addWidget(info)

        self.layout.addStretch()

        admin_label = QLabel("Administrator privileges are recommended for installation.")
        admin_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        admin_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        admin_label.setStyleSheet("color: #d93025;")
        if _is_admin():
            admin_label.setText("Running with Administrator privileges.")
            admin_label.setStyleSheet("color: #1e8e3e;")
        self.layout.addWidget(admin_label)


class ServerConfigPage(WizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)

        title = QLabel("Service Configuration")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #202124;")
        self.layout.addWidget(title)

        self.layout.addSpacing(15)

        group_inv = QGroupBox("Inventory Service (port 8003)")
        group_inv.setFont(QFont("Segoe UI", 10))
        form_inv = QFormLayout()
        self.inventory_url = QLineEdit(DEFAULT_INVENTORY_URL)
        self.inventory_url.setFont(QFont("Consolas", 10))
        form_inv.addRow("URL:", self.inventory_url)
        group_inv.setLayout(form_inv)
        self.layout.addWidget(group_inv)

        group_logs = QGroupBox("Logs Service (port 9201)")
        group_logs.setFont(QFont("Segoe UI", 10))
        form_logs = QFormLayout()
        self.logs_url = QLineEdit(DEFAULT_LOGS_URL)
        self.logs_url.setFont(QFont("Consolas", 10))
        form_logs.addRow("URL:", self.logs_url)
        group_logs.setLayout(form_logs)
        self.layout.addWidget(group_logs)

        hint = QLabel("For remote servers, replace localhost with the server IP or hostname.")
        hint.setFont(QFont("Segoe UI", 9))
        hint.setStyleSheet("color: #80868b;")
        hint.setWordWrap(True)
        self.layout.addWidget(hint)

        self.layout.addStretch()

        self.test_btn = QPushButton("Test Connection")
        self.test_btn.setFont(QFont("Segoe UI", 10))
        self.test_btn.setStyleSheet(
            "QPushButton { background-color: #1a73e8; color: white; padding: 8px 20px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #1557b0; }"
            "QPushButton:disabled { background-color: #949494; }"
        )
        self.layout.addWidget(self.test_btn, alignment=Qt.AlignmentFlag.AlignRight)

        self.status_label = QLabel()
        self.status_label.setFont(QFont("Segoe UI", 9))
        self.status_label.setWordWrap(True)
        self.layout.addWidget(self.status_label)

    def validate(self):
        if not self.inventory_url.text().strip():
            return False, "Inventory Service URL is required"
        if not self.logs_url.text().strip():
            return False, "Logs Service URL is required"
        return True, ""


class EnrollmentPage(WizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)

        title = QLabel("Agent Enrollment")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #202124;")
        self.layout.addWidget(title)

        self.layout.addSpacing(10)

        self.info_label = QLabel("Registering this machine with the VANT-SIEM Inventory service...")
        self.info_label.setFont(QFont("Segoe UI", 10))
        self.info_label.setWordWrap(True)
        self.layout.addWidget(self.info_label)

        self.layout.addSpacing(15)

        self.enroll_text = QTextEdit()
        self.enroll_text.setReadOnly(True)
        self.enroll_text.setFont(QFont("Consolas", 9))
        self.enroll_text.setMaximumHeight(140)
        self.enroll_text.setStyleSheet("background-color: #f8f9fa; border: 1px solid #dadce0; border-radius: 4px;")
        self.layout.addWidget(self.enroll_text)

        self.enroll_btn = QPushButton("Enroll Agent")
        self.enroll_btn.setFont(QFont("Segoe UI", 10))
        self.enroll_btn.setStyleSheet(
            "QPushButton { background-color: #1e8e3e; color: white; padding: 8px 20px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #137333; }"
            "QPushButton:disabled { background-color: #949494; }"
        )
        self.layout.addWidget(self.enroll_btn, alignment=Qt.AlignmentFlag.AlignRight)

        self.layout.addStretch()

    def set_machine_info(self, hostname, mac, os_name, os_ver, os_arch, ip_address):
        self.enroll_text.setText(
            f"Hostname:      {hostname}\n"
            f"MAC Address:   {mac}\n"
            f"IP Address:    {ip_address}\n"
            f"OS:            {os_name} {os_ver}\n"
            f"Architecture:  {os_arch}\n"
            f"Agent Version: {_VERSION}"
        )


class InstallPage(WizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)

        title = QLabel("Install Agent")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #202124;")
        self.layout.addWidget(title)

        self.layout.addSpacing(15)

        group = QGroupBox("Installation Directory")
        group.setFont(QFont("Segoe UI", 10))
        form = QFormLayout()
        self.install_dir = QLineEdit(r"C:\Program Files\VANT-Agent")
        self.install_dir.setFont(QFont("Consolas", 10))
        self.install_dir.setReadOnly(True)
        form.addRow("Path:", self.install_dir)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        form.addRow("", browse_btn)
        group.setLayout(form)
        self.layout.addWidget(group)

        self.layout.addStretch()

        self.progress = QProgressBar()
        self.progress.setStyleSheet(
            "QProgressBar { border: 1px solid #dadce0; border-radius: 4px; text-align: center; }"
            "QProgressBar::chunk { background-color: #1a73e8; }"
        )
        self.layout.addWidget(self.progress)

        self.status_label = QLabel()
        self.status_label.setFont(QFont("Segoe UI", 9))
        self.status_label.setWordWrap(True)
        self.layout.addWidget(self.status_label)

        self.install_btn = QPushButton("Install")
        self.install_btn.setFont(QFont("Segoe UI", 10))
        self.install_btn.setStyleSheet(
            "QPushButton { background-color: #1a73e8; color: white; padding: 8px 20px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #1557b0; }"
            "QPushButton:disabled { background-color: #949494; }"
        )
        self.layout.addWidget(self.install_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Install Directory", self.install_dir.text())
        if d:
            self.install_dir.setText(d)


class CompletePage(WizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)

        title = QLabel("Installation Complete")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #1e8e3e;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(title)

        self.layout.addSpacing(20)

        self.summary = QTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setFont(QFont("Consolas", 9))
        self.summary.setStyleSheet("background-color: #f8f9fa; border: 1px solid #dadce0; border-radius: 4px;")
        self.layout.addWidget(self.summary)

        self.layout.addStretch()


class InstallerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"VANT-Agent Setup v{_VERSION}")
        self.setMinimumSize(600, 520)
        self.resize(640, 560)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowMaximizeButtonHint)

        self.config = {}

        self._build_ui()
        self._go_to_page(0)

    def _build_ui(self):
        self.central = QWidget()
        self.setCentralWidget(self.central)
        self.main_layout = QVBoxLayout(self.central)

        self.stack = QStackedWidget()
        self.pages = [
            WelcomePage(self),
            ServerConfigPage(self),
            EnrollmentPage(self),
            InstallPage(self),
            CompletePage(self),
        ]
        for p in self.pages:
            self.stack.addWidget(p)
        self.main_layout.addWidget(self.stack)

        nav = QHBoxLayout()
        self.back_btn = QPushButton("Back")
        self.back_btn.setFixedWidth(100)
        self.back_btn.clicked.connect(self._prev)
        nav.addWidget(self.back_btn)

        nav.addStretch()

        self.next_btn = QPushButton("Next")
        self.next_btn.setFixedWidth(100)
        self.next_btn.clicked.connect(self._next)
        self.next_btn.setStyleSheet(
            "QPushButton { background-color: #1a73e8; color: white; padding: 8px 20px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #1557b0; }"
        )
        nav.addWidget(self.next_btn)

        self.main_layout.addLayout(nav)

        self.server_page = self.pages[1]
        self.enrollment_page = self.pages[2]
        self.install_page = self.pages[3]

        self.server_page.test_btn.clicked.connect(self._test_connection)
        self.enrollment_page.enroll_btn.clicked.connect(self._enroll)
        self.install_page.install_btn.clicked.connect(self._install)

        self._updating = False

    def _go_to_page(self, idx):
        self._updating = True
        self.stack.setCurrentIndex(idx)
        self.back_btn.setVisible(idx > 0)
        self.next_btn.setText("Finish" if idx == len(self.pages) - 1 else "Next")
        self._updating = False

    def _next(self):
        if self._updating:
            return
        idx = self.stack.currentIndex()
        if idx == 1:
            ok, msg = self.server_page.validate()
            if not ok:
                QMessageBox.warning(self, "Validation Error", msg)
                return
            self.config["inventory_url"] = self.server_page.inventory_url.text().strip()
            self.config["logs_url"] = self.server_page.logs_url.text().strip()
        elif idx == 4:
            self.close()
            return
        self._go_to_page(idx + 1)
        if idx + 1 == 2:
            self._setup_enrollment()

    def _prev(self):
        if self._updating:
            return
        self._go_to_page(self.stack.currentIndex() - 1)

    def _test_connection(self):
        inv_url = self.server_page.inventory_url.text().strip()
        logs_url = self.server_page.logs_url.text().strip()
        if not inv_url or not logs_url:
            QMessageBox.warning(self, "Error", "Please fill in both service URLs.")
            return

        self.server_page.test_btn.setEnabled(False)
        self.server_page.test_btn.setText("Testing...")
        self.server_page.status_label.setText("")

        self._conn_thread = ConnectionTestThread(inv_url, logs_url)
        self._conn_thread.result.connect(self._on_conn_result)
        self._conn_thread.start()

    def _on_conn_result(self, ok, results):
        self.server_page.test_btn.setEnabled(True)
        self.server_page.test_btn.setText("Test Connection")

        lines = []
        for name, (success, msg) in results.items():
            icon = "OK" if success else "FAILED"
            lines.append(f"[{icon}] {msg}")

        self.server_page.status_label.setText("\n".join(lines))
        if ok:
            self.server_page.status_label.setStyleSheet("color: #1e8e3e;")
        else:
            self.server_page.status_label.setStyleSheet("color: #d93025;")

    def _setup_enrollment(self):
        hostname = _get_hostname()
        mac = _get_mac()
        ip_address = _get_local_ip()
        os_type, os_ver = _map_os_type()
        os_arch = platform.machine()

        os_display = {
            "windows": "Windows",
            "linux": "Linux",
            "macos": "macOS",
        }
        os_display_name = os_display.get(os_type, os_type.title())

        self.enrollment_page.set_machine_info(hostname, mac, os_display_name, os_ver, os_arch, ip_address)
        self.config["_os_type"] = os_type
        self.config["_os_version"] = os_ver
        self.config["_os_arch"] = os_arch
        self.config["_ip_address"] = ip_address
        self.config["_hostname"] = hostname
        self.config["_mac"] = mac

        inv_url = self.config.get("inventory_url", "N/A")
        self.enrollment_page.info_label.setText(
            f"Ready to enroll with: {inv_url}"
        )

    def _enroll(self):
        self.enrollment_page.enroll_btn.setEnabled(False)
        self.enrollment_page.enroll_btn.setText("Enrolling...")
        self.enrollment_page.info_label.setText("Sending registration request...")

        self._enroll_thread = EnrollmentThread(
            self.config["inventory_url"],
            self.config.get("_hostname", _get_hostname()),
            self.config.get("_mac", _get_mac()),
            self.config["_os_type"],
            self.config["_os_version"],
            self.config["_os_arch"],
            self.config["_ip_address"],
        )
        self._enroll_thread.result.connect(self._on_enroll_result)
        self._enroll_thread.start()

    def _on_enroll_result(self, ok, data, error):
        self.enrollment_page.enroll_btn.setEnabled(True)
        self.enrollment_page.enroll_btn.setText("Enroll Agent")
        if ok:
            self.config["agent_id"] = data.get("agent_id", "")
            self.config["enrollment_status"] = data.get("status", "online")
            self.config["created"] = data.get("created", False)
            self.enrollment_page.info_label.setStyleSheet("color: #1e8e3e;")
            action = "registered" if self.config["created"] else "found (already enrolled)"
            self.enrollment_page.info_label.setText(
                f"Agent {action} successfully!\n"
                f"Agent ID: {self.config['agent_id']}\n"
                f"Status: {self.config['enrollment_status']}"
            )
        else:
            self.enrollment_page.info_label.setStyleSheet("color: #d93025;")
            self.enrollment_page.info_label.setText(f"Enrollment failed: {error}")

    def _install(self):
        self.install_page.install_btn.setEnabled(False)
        self.install_page.install_btn.setText("Installing...")
        self.install_page.progress.setValue(0)

        install_dir = self.install_page.install_dir.text().strip()
        self._inst_thread = InstallerThread(self.config, install_dir)
        self._inst_thread.progress.connect(self._on_inst_progress)
        self._inst_thread.finished.connect(self._on_inst_finished)
        self._inst_thread.start()

    def _on_inst_progress(self, pct, msg):
        self.install_page.progress.setValue(pct)
        self.install_page.status_label.setText(msg)

    def _on_inst_finished(self, ok, msg):
        self.install_page.install_btn.setEnabled(True)
        self.install_page.install_btn.setText("Install")
        if ok:
            summary = (
                f"Installation Directory: {self.install_page.install_dir.text()}\n"
                f"Inventory Service: {self.config.get('inventory_url', 'N/A')}\n"
                f"Logs Service: {self.config.get('logs_url', 'N/A')}\n"
                f"Agent ID: {self.config.get('agent_id', 'N/A')}\n"
                f"Status: {msg}"
            )
            self.pages[4].summary.setText(summary)
            self._go_to_page(4)
        else:
            QMessageBox.critical(self, "Installation Failed", msg)


def main():
    if not _is_admin():
        try:
            exe = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
            params = ' '.join([f'"{a}"' for a in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params, None, 1
            )
            sys.exit(0)
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    app.setStyleSheet("""
        QMainWindow { background-color: #ffffff; }
        QGroupBox { font-weight: bold; padding-top: 10px; margin-top: 10px; }
        QGroupBox::title { color: #1a73e8; subcontrol-origin: margin; left: 10px; padding: 0 5px; }
        QTextEdit { padding: 8px; }
        QLineEdit { padding: 4px; border: 1px solid #dadce0; border-radius: 3px; }
        QLabel { color: #3c4043; }
    """)

    window = InstallerWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
