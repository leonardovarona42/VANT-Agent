import hashlib
import hmac
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from PyQt6 import QtCore, QtGui, QtWidgets


DEFAULT_AGENT_SHARED_SECRET = "VANT-SIEM-AGENT-BOOTSTRAP-2026"


def _runtime_root():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parents[2]


def _source_windows_dir():
    return Path(__file__).resolve().parent


def _windows_assets_dir():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return _runtime_root() / "package"
    return _source_windows_dir() / "package"


def _resolve_windows_assets_dir():
    candidates = [
        _windows_assets_dir(),
        _runtime_root() / "package",
        _runtime_root(),
        _source_windows_dir() / "package",
    ]
    seen = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if (candidate / "Install-OpenSearchAgent.ps1").exists() and (candidate / "config.yaml").exists():
            return candidate
    return candidates[0]


def _logo_path():
    return _runtime_root() / "staticfiles" / "img" / "logo.png"


def _bootstrap_key_path():
    bundled = _resolve_windows_assets_dir() / "bootstrap.key"
    if bundled.exists():
        return bundled
    return _source_windows_dir() / "bootstrap.key"


def _is_admin():
    if sys.platform.startswith("win"):
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False


def _default_paths():
    return {
        "snort": "C:/Snort",
        "suricata": "C:/suricata/logs/eve.json",
        "postgres": "C:/Program Files/PostgreSQL/16/data/log/postgresql.log",
        "file_logs": "C:/ProgramData/VANT/logs/audit.log",
    }


def _system_install_dir():
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    return Path(program_files) / "VANT" / "OpenSearchAgent"


def _ad_event_channels():
    return [
        "Security",
        "System",
        "Application",
        "Directory Service",
        "DNS Server",
        "DFS Replication",
        "Active Directory Web Services",
    ]


class WelcomePage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Bienvenida")
        self.setSubTitle("Vamos a instalar el agente OpenSearch de VANT-SIEM en Windows.")

        layout = QtWidgets.QVBoxLayout()
        status_box = QtWidgets.QGroupBox("Estado del sistema")
        status_layout = QtWidgets.QFormLayout()
        status_layout.addRow("Sistema operativo:", QtWidgets.QLabel("Windows"))
        status_layout.addRow(
            "Permisos:",
            QtWidgets.QLabel("Administrador confirmado" if _is_admin() else "Requiere privilegios"),
        )
        status_layout.addRow("Instalador:", QtWidgets.QLabel("Modo grafico"))
        status_box.setLayout(status_layout)

        hint = QtWidgets.QLabel(
            "Este setup empaqueta el agente de Windows con interfaz grafica y luego instala el servicio programado."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #6b7280;")

        layout.addWidget(status_box)
        layout.addWidget(hint)
        layout.addStretch()
        self.setLayout(layout)


class IdentityPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Identidad del agente")
        self.setSubTitle("Define como se identificara este agente.")

        layout = QtWidgets.QFormLayout()
        self.agent_id = QtWidgets.QLineEdit("agent-001")
        self.host_name = QtWidgets.QLineEdit(socket.gethostname())
        self.interval = QtWidgets.QSpinBox()
        self.interval.setRange(1, 3600)
        self.interval.setValue(10)

        layout.addRow("Agent ID:", self.agent_id)
        layout.addRow("Host Name:", self.host_name)
        layout.addRow("Intervalo (segundos):", self.interval)
        self.setLayout(layout)

        self.registerField("agent_id*", self.agent_id)
        self.registerField("host_name*", self.host_name)
        self.registerField("interval", self.interval)

    def isComplete(self):
        return bool(self.agent_id.text().strip()) and bool(self.host_name.text().strip())


class ConnectionPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Conexion a OpenSearch")
        self.setSubTitle("Configura IPs, puertos y seguridad.")

        layout = QtWidgets.QFormLayout()

        self.server_host = QtWidgets.QLineEdit("192.168.12.43")
        self.server_port = QtWidgets.QSpinBox()
        self.server_port.setRange(1, 65535)
        self.server_port.setValue(8000)
        self.server_https = QtWidgets.QCheckBox("Usar HTTPS para VANT-SIEM")

        self.opensearch_host = QtWidgets.QLineEdit("192.168.12.43")
        self.opensearch_port = QtWidgets.QSpinBox()
        self.opensearch_port.setRange(1, 65535)
        self.opensearch_port.setValue(9201)

        self.endpoint = QtWidgets.QLineEdit()
        self.source_endpoint = QtWidgets.QLineEdit()
        self.timeout = QtWidgets.QSpinBox()
        self.timeout.setRange(1, 120)
        self.timeout.setValue(10)

        self.tls_enabled = QtWidgets.QCheckBox("Habilitar TLS")
        self.tls_verify = QtWidgets.QCheckBox("Verificar certificado")
        self.tls_verify.setChecked(False)
        self.ca_cert = QtWidgets.QLineEdit("")

        self.test_button = QtWidgets.QPushButton("Probar conexion")
        self.test_status = QtWidgets.QLabel("Sin pruebas ejecutadas.")
        self.test_status.setStyleSheet("color: #6b7280;")
        self.test_button.clicked.connect(self._on_test)

        layout.addRow("Servidor VANT-SIEM IP:", self.server_host)
        layout.addRow("Servidor VANT-SIEM Puerto:", self.server_port)
        layout.addRow(self.server_https)
        layout.addRow("OpenSearch IP:", self.opensearch_host)
        layout.addRow("OpenSearch Puerto:", self.opensearch_port)
        layout.addRow("Timeout (segundos):", self.timeout)
        layout.addRow(self.tls_enabled)
        layout.addRow(self.tls_verify)
        layout.addRow("Certificado CA:", self.ca_cert)
        layout.addRow(self.test_button, self.test_status)
        self.setLayout(layout)

        self.endpoint.setVisible(False)
        self.source_endpoint.setVisible(False)

        self.registerField("server_host*", self.server_host)
        self.registerField("server_port", self.server_port)
        self.registerField("server_https", self.server_https)
        self.registerField("endpoint*", self.endpoint)
        self.registerField("source_endpoint*", self.source_endpoint)
        self.registerField("timeout", self.timeout)
        self.registerField("tls_enabled", self.tls_enabled)
        self.registerField("tls_verify", self.tls_verify)
        self.registerField("ca_cert", self.ca_cert)
        self.registerField("opensearch_host*", self.opensearch_host)
        self.registerField("opensearch_port", self.opensearch_port)

        self._notify_complete = lambda *_: self.completeChanged.emit()
        self.server_host.textChanged.connect(self._refresh_endpoints)
        self.server_host.textChanged.connect(self._notify_complete)
        self.server_port.valueChanged.connect(self._refresh_endpoints)
        self.server_port.valueChanged.connect(self._notify_complete)
        self.opensearch_host.textChanged.connect(self._refresh_endpoints)
        self.opensearch_host.textChanged.connect(self._notify_complete)
        self.opensearch_port.valueChanged.connect(self._refresh_endpoints)
        self.opensearch_port.valueChanged.connect(self._notify_complete)
        self.tls_enabled.stateChanged.connect(self._refresh_endpoints)
        self.tls_enabled.stateChanged.connect(self._notify_complete)
        self._refresh_endpoints()

    def _load_bootstrap_key(self):
        env_key = os.environ.get("VANT_AGENT_BOOTSTRAP_KEY", "").strip()
        if env_key:
            return env_key
        env_shared = os.environ.get("VANT_AGENT_SHARED_SECRET", "").strip()
        if env_shared:
            return env_shared
        path = _bootstrap_key_path()
        if path.exists():
            try:
                return path.read_text(encoding="utf-8").strip()
            except Exception:
                return ""
        return ""

    def _fetch_bootstrap_secret(self):
        url = self._build_bootstrap_url()
        if not url:
            return ""
        try:
            headers = {"X-Agent-Id": self.wizard().field("agent_id") or ""}
            response = requests.get(url, headers=headers, timeout=6)
            if "application/json" not in response.headers.get("Content-Type", ""):
                return ""
            data = response.json()
            if response.status_code == 200 and data.get("ok") and data.get("secret"):
                return data.get("secret", "")
        except Exception:
            return ""
        return ""

    def _build_bootstrap_url(self):
        scheme = "https" if self.server_https.isChecked() else "http"
        host = self.server_host.text().strip()
        port = self.server_port.value()
        if not host:
            return ""
        return f"{scheme}://{host}:{port}/api/agent/bootstrap/"

    def _build_enroll_url(self):
        scheme = "https" if self.server_https.isChecked() else "http"
        host = self.server_host.text().strip()
        port = self.server_port.value()
        return f"{scheme}://{host}:{port}/api/agent/enroll/"

    def _sign_request(self, secret, agent_id, host_name, timestamp):
        message = f"{agent_id}:{host_name}:{timestamp}".encode("utf-8")
        return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()

    def _refresh_endpoints(self):
        scheme = "https" if self.tls_enabled.isChecked() else "http"
        host = self.opensearch_host.text().strip()
        port = self.opensearch_port.value()
        self.endpoint.setText(f"{scheme}://{host}:{port}/api/v1/events/bulk")
        self.source_endpoint.setText(f"{scheme}://{host}:{port}/api/v1/sources/upsert")
        self.completeChanged.emit()

    def isComplete(self):
        return all(
            [
                bool(self.server_host.text().strip()),
                bool(self.opensearch_host.text().strip()),
                bool(self.endpoint.text().strip()),
                bool(self.source_endpoint.text().strip()),
            ]
        )

    def _probe_endpoint(self, endpoint):
        try:
            parsed = urlparse(endpoint)
            if not parsed.scheme or not parsed.hostname:
                return False
            probe_url = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or 9201}/health"
            verify = False
            if self.tls_enabled.isChecked():
                verify = self.ca_cert.text().strip() or self.tls_verify.isChecked()
            response = requests.get(probe_url, timeout=5, verify=verify)
            return response.ok
        except Exception:
            return False

    def _on_test(self):
        wizard = self.wizard()
        auth_page = wizard.page(AgentInstallerWizard.PAGE_AUTH)
        auth_mode = auth_page.auth_mode.currentText()

        if auth_mode == "none":
            shared_secret = self._load_bootstrap_key() or self._fetch_bootstrap_secret() or DEFAULT_AGENT_SHARED_SECRET
            timestamp = str(int(time.time()))
            signature = self._sign_request(
                shared_secret,
                wizard.field("agent_id"),
                wizard.field("host_name"),
                timestamp,
            )
            payload = {
                "agent_id": wizard.field("agent_id"),
                "host_name": wizard.field("host_name"),
                "timestamp": timestamp,
                "signature": signature,
                "install_owner_account": self._owner_account(),
            }
            try:
                response = requests.post(self._build_enroll_url(), json=payload, timeout=8)
                data = response.json() if "application/json" in response.headers.get("Content-Type", "") else {}
            except Exception as exc:
                self.test_status.setText(f"Error al conectar: {exc}")
                self.test_status.setStyleSheet("color: #dc2626;")
                return

            if response.status_code != 200 or not data.get("ok"):
                if response.status_code == 400 and "HTTPS" in response.text:
                    self.test_status.setText("Servidor en HTTP. Desactiva HTTPS o inicia run_https.ps1.")
                else:
                    self.test_status.setText(data.get("error") or "Agente no autorizado para enrolamiento.")
                self.test_status.setStyleSheet("color: #dc2626;")
                return

            auth_page.auth_mode.setCurrentText("token")
            auth_page.token.setText(data.get("token", ""))

        self._refresh_endpoints()
        if self._probe_endpoint(self.endpoint.text().strip()):
            self.test_status.setText("Conexion exitosa y token obtenido.")
            self.test_status.setStyleSheet("color: #16a34a;")
        else:
            self.test_status.setText("Token obtenido, pero endpoint no responde.")
            self.test_status.setStyleSheet("color: #f59e0b;")

    def _owner_account(self):
        installed_by_user = os.environ.get("USERNAME", "").strip()
        installed_by_domain = (
            os.environ.get("USERDOMAIN", "").strip()
            or os.environ.get("COMPUTERNAME", "").strip()
        )
        if installed_by_domain and installed_by_user:
            return f"{installed_by_domain}\\{installed_by_user}"
        return installed_by_user


class AuthPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Autenticacion")
        self.setSubTitle("Selecciona el metodo de autenticacion.")

        layout = QtWidgets.QVBoxLayout()
        self.auth_mode = QtWidgets.QComboBox()
        self.auth_mode.addItems(["none", "basic", "token"])
        self.auth_mode.currentTextChanged.connect(self._update_fields)

        self.user = QtWidgets.QLineEdit()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.token = QtWidgets.QLineEdit()

        form = QtWidgets.QFormLayout()
        form.addRow("Modo:", self.auth_mode)
        form.addRow("Usuario:", self.user)
        form.addRow("Password:", self.password)
        form.addRow("Token:", self.token)
        layout.addLayout(form)
        layout.addStretch()
        self.setLayout(layout)
        self._update_fields(self.auth_mode.currentText())

        self.registerField("auth_mode", self.auth_mode, "currentText")
        self.registerField("auth_user", self.user)
        self.registerField("auth_password", self.password)
        self.registerField("auth_token", self.token)

    def _update_fields(self, mode):
        basic = mode == "basic"
        token = mode == "token"
        self.user.setEnabled(basic)
        self.password.setEnabled(basic)
        self.token.setEnabled(token)


class CollectorsPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Recolectores")
        self.setSubTitle("Activa las fuentes de eventos y perfiles de auditoria.")

        layout = QtWidgets.QVBoxLayout()
        defaults = _default_paths()

        ids_group = QtWidgets.QGroupBox("IDS y logs de aplicacion")
        ids_form = QtWidgets.QFormLayout()
        self.snort = QtWidgets.QCheckBox("Snort")
        self.snort_path = QtWidgets.QLineEdit(defaults["snort"])
        self.suricata = QtWidgets.QCheckBox("Suricata")
        self.suricata_path = QtWidgets.QLineEdit(defaults["suricata"])
        self.postgres = QtWidgets.QCheckBox("PostgreSQL")
        self.postgres_path = QtWidgets.QLineEdit(defaults["postgres"])
        self.file_logs = QtWidgets.QCheckBox("File Logs")
        self.file_logs_path = QtWidgets.QLineEdit(defaults["file_logs"])

        ids_form.addRow(self.snort, self.snort_path)
        ids_form.addRow(self.suricata, self.suricata_path)
        ids_form.addRow(self.postgres, self.postgres_path)
        ids_form.addRow(self.file_logs, self.file_logs_path)
        ids_group.setLayout(ids_form)

        winlog_group = QtWidgets.QGroupBox("Windows Event Log y Active Directory")
        self.winlog = QtWidgets.QCheckBox("Windows Event Log")
        self.winlog_channel = QtWidgets.QComboBox()
        self.winlog_channel.addItems(_ad_event_channels())
        self.winlog_ad_profile = QtWidgets.QCheckBox("Habilitar perfil de auditoria AD/Domain Controller")
        self.winlog_ad_profile.setChecked(True)
        self.winlog_channels = QtWidgets.QPlainTextEdit()
        self.winlog_channels.setPlaceholderText(
            "Canales por linea. Ejemplo:\nSecurity\nDirectory Service\nDNS Server"
        )
        self.winlog_channels.setFixedHeight(110)
        self.winlog_help = QtWidgets.QLabel(
            "El perfil AD agrega Security, Directory Service, DNS Server, DFS Replication y Active Directory Web Services."
        )
        self.winlog_help.setWordWrap(True)
        self.winlog_help.setStyleSheet("color: #6b7280;")

        winlog_form = QtWidgets.QFormLayout()
        winlog_form.addRow(self.winlog, self.winlog_channel)
        winlog_form.addRow(self.winlog_ad_profile)
        winlog_form.addRow("Canales adicionales / finales:", self.winlog_channels)
        winlog_form.addRow(self.winlog_help)
        winlog_group.setLayout(winlog_form)

        layout.addWidget(ids_group)
        layout.addWidget(winlog_group)
        self.setLayout(layout)

        self.registerField("snort_enabled", self.snort)
        self.registerField("snort_path", self.snort_path)
        self.registerField("suricata_enabled", self.suricata)
        self.registerField("suricata_path", self.suricata_path)
        self.registerField("winlog_enabled", self.winlog)
        self.registerField("winlog_channel", self.winlog_channel, "currentText")
        self.registerField("winlog_ad_profile", self.winlog_ad_profile)
        self.registerField("postgres_enabled", self.postgres)
        self.registerField("postgres_path", self.postgres_path)
        self.registerField("file_logs_enabled", self.file_logs)
        self.registerField("file_logs_path", self.file_logs_path)

        self.winlog.stateChanged.connect(self._refresh_winlog_channels)
        self.winlog_ad_profile.stateChanged.connect(self._refresh_winlog_channels)
        self.winlog_channel.currentTextChanged.connect(self._refresh_winlog_channels)
        self._refresh_winlog_channels()

    def _refresh_winlog_channels(self):
        channels = []
        primary = self.winlog_channel.currentText().strip()
        if primary:
            channels.append(primary)
        if self.winlog_ad_profile.isChecked():
            for channel in _ad_event_channels():
                if channel not in channels:
                    channels.append(channel)
        self.winlog_channels.setPlainText("\n".join(channels))


class SummaryPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Resumen")
        self.setSubTitle("Revisa la configuracion antes de instalar.")

        layout = QtWidgets.QVBoxLayout()
        self.preview = QtWidgets.QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setStyleSheet("font-family: Consolas, monospace;")

        self.install_service = QtWidgets.QCheckBox("Instalar como tarea programada")
        self.install_service.setChecked(True)

        layout.addWidget(self.preview)
        layout.addWidget(self.install_service)
        self.setLayout(layout)

    def initializePage(self):
        self.preview.setPlainText(self.wizard().build_config_preview(mask_secrets=True))


class ProgressPage(QtWidgets.QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Instalacion en progreso")
        self.setSubTitle("Aplicando la configuracion y registrando el agente.")
        self.setFinalPage(True)
        self._done = False

        layout = QtWidgets.QVBoxLayout()
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("font-family: Consolas, monospace;")
        layout.addWidget(self.progress)
        layout.addWidget(self.log)
        self.setLayout(layout)

    def initializePage(self):
        self._done = False
        self.progress.setValue(5)
        self.log.clear()
        self.log.appendPlainText("Preparando paquete interno del instalador...")

        package_dir = self.wizard().stage_package()
        if not package_dir:
            error_text = self.wizard().stage_error() or "Error no especificado al preparar el payload."
            self.log.appendPlainText("No se pudo preparar el paquete del agente.")
            self.log.appendPlainText(error_text)
            self.completeChanged.emit()
            return

        self.progress.setValue(40)
        self.log.appendPlainText(f"Paquete preparado en: {package_dir}")

        if not self.wizard().page(AgentInstallerWizard.PAGE_SUMMARY).install_service.isChecked():
            self.log.appendPlainText("Instalacion omitida por el usuario.")
            self.progress.setValue(100)
            self._done = True
            self.completeChanged.emit()
            return

        self.log.appendPlainText("Ejecutando instalador PowerShell del agente...")
        self.log.appendPlainText(
            f"Diagnostico setup: elevated={_is_admin()} user={os.environ.get('USERNAME', '')}"
        )
        ok, output = self.wizard().install_windows_package(package_dir)
        if output.strip():
            self.log.appendPlainText(output.strip())

        if ok:
            self.log.appendPlainText("Instalacion completada correctamente.")
            self.progress.setValue(100)
            self._done = True
        else:
            self.log.appendPlainText("La instalacion fallo. Revisa el log anterior.")
            self.progress.setValue(100)

        self.completeChanged.emit()

    def isComplete(self):
        return self._done


class AgentInstallerWizard(QtWidgets.QWizard):
    PAGE_WELCOME = 0
    PAGE_IDENTITY = 1
    PAGE_CONNECTION = 2
    PAGE_AUTH = 3
    PAGE_COLLECTORS = 4
    PAGE_SUMMARY = 5
    PAGE_PROGRESS = 6

    def __init__(self):
        super().__init__()
        self._staged_dir = None
        self._stage_error = ""
        self.setWindowTitle("VANT-SIEM Windows Agent Setup")
        self.setWizardStyle(QtWidgets.QWizard.WizardStyle.ModernStyle)

        logo = _logo_path()
        if logo.exists():
            icon = QtGui.QIcon(str(logo))
            self.setWindowIcon(icon)
            self.setPixmap(
                QtWidgets.QWizard.WizardPixmap.LogoPixmap,
                QtGui.QPixmap(str(logo)).scaled(64, 64, QtCore.Qt.AspectRatioMode.KeepAspectRatio),
            )

        self.setPage(self.PAGE_WELCOME, WelcomePage())
        self.setPage(self.PAGE_IDENTITY, IdentityPage())
        self.setPage(self.PAGE_CONNECTION, ConnectionPage())
        self.setPage(self.PAGE_AUTH, AuthPage())
        self.setPage(self.PAGE_COLLECTORS, CollectorsPage())
        self.setPage(self.PAGE_SUMMARY, SummaryPage())
        self.setPage(self.PAGE_PROGRESS, ProgressPage())

        self.setStartId(self.PAGE_WELCOME)
        self.setOption(QtWidgets.QWizard.WizardOption.NoBackButtonOnStartPage, True)

    def accept(self):
        QtWidgets.QMessageBox.information(
            self,
            "Instalacion completada",
            "El setup grafico termino correctamente.",
        )
        super().accept()

    def build_config_preview(self, mask_secrets=False):
        import yaml

        data = self.build_config_data(mask_secrets=mask_secrets)
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)

    def build_config_data(self, mask_secrets=False):
        auth_password = self.field("auth_password") or ""
        auth_token = self.field("auth_token") or ""
        installed_by_user = os.environ.get("USERNAME", "").strip()
        installed_by_domain = os.environ.get("USERDOMAIN", "").strip()
        owner_account = f"{installed_by_domain}\\{installed_by_user}" if installed_by_domain and installed_by_user else installed_by_user
        generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if mask_secrets:
            auth_password = "******" if auth_password else ""
            auth_token = "******" if auth_token else ""

        require_https = self.page(self.PAGE_CONNECTION).server_https.isChecked()
        collectors_page = self.page(self.PAGE_COLLECTORS)
        winlog_channels = [
            line.strip()
            for line in collectors_page.winlog_channels.toPlainText().splitlines()
            if line.strip()
        ]
        return {
            "agent": {
                "id": self.field("agent_id"),
                "host_name": self.field("host_name"),
                "interval_seconds": int(self.field("interval")),
            },
            "output": {
                "endpoint": self.field("endpoint"),
                "source_endpoint": self.field("source_endpoint"),
                "timeout_seconds": int(self.field("timeout")),
                "auth": {
                    "mode": self.field("auth_mode"),
                    "username": self.field("auth_user"),
                    "password": auth_password,
                    "token": auth_token,
                },
                "tls": {
                    "enabled": bool(self.field("tls_enabled")),
                    "verify": bool(self.field("tls_verify")),
                    "ca_cert": self.field("ca_cert"),
                },
            },
            "control": {
                "server_url": self._build_server_url(),
                "require_https": bool(require_https),
                "poll_seconds": 30,
                "inventory_seconds": 86400,
                "dlp_poll_seconds": 60,
                "dlp_scan_seconds": 30,
            },
            "asset_audit": {
                "enabled": True,
            },
            "aegis_dlp": {
                "enabled": True,
                "max_file_size_mb": 25,
                "max_files_per_scan": 12000,
                "max_scan_seconds": 20,
                "scan_paths": [],
                "monitored_extensions": [
                    ".txt", ".log", ".csv", ".json", ".xml", ".md", ".doc", ".docx", ".docm", ".rtf",
                    ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".odt", ".ods", ".odp", ".ini",
                    ".conf", ".cfg", ".yaml", ".yml", ".ps1", ".bat", ".cmd", ".sql", ".env", ".properties",
                    ".html", ".htm", ".pdf",
                ],
            },
            "install_metadata": {
                "owner_account": owner_account,
                "enrolled_by_user": installed_by_user,
                "enrolled_by_domain": installed_by_domain,
                "generated_at": generated_at,
                "installer_profile": "windows_gui",
            },
            "collectors": {
                "snort": {
                    "enabled": bool(self.field("snort_enabled")),
                    "path": self.field("snort_path"),
                    "start_position": "beginning",
                    "max_lines_per_cycle": 400,
                },
                "suricata": {
                    "enabled": bool(self.field("suricata_enabled")),
                    "path": self.field("suricata_path"),
                    "start_position": "beginning",
                    "max_lines_per_cycle": 600,
                },
                "windows_eventlog": {
                    "enabled": bool(self.field("winlog_enabled")),
                    "channel": self.field("winlog_channel"),
                    "channels": winlog_channels or ["Security"],
                },
                "postgres": {
                    "enabled": bool(self.field("postgres_enabled")),
                    "path": self.field("postgres_path"),
                    "start_position": "end",
                    "max_lines_per_cycle": 400,
                },
                "file_logs": {
                    "enabled": bool(self.field("file_logs_enabled")),
                    "items": [
                        {
                            "enabled": bool(self.field("file_logs_enabled")),
                            "source_name": "windows-custom-audit",
                            "path": self.field("file_logs_path"),
                            "event_category": "windows.custom.audit",
                            "severity": "info",
                            "tags": ["windows", "audit", "custom"],
                            "start_position": "end",
                            "max_lines_per_cycle": 400,
                        }
                    ],
                },
            },
        }

    def _build_server_url(self):
        page = self.page(self.PAGE_CONNECTION)
        scheme = "https" if page.server_https.isChecked() else "http"
        host = page.server_host.text().strip()
        port = page.server_port.value()
        return f"{scheme}://{host}:{port}"

    def stage_package(self):
        self._stage_error = ""
        try:
            source_dir = _resolve_windows_assets_dir()
            if not source_dir.exists():
                self._stage_error = f"No se encontro el payload embebido del instalador: {source_dir}"
                return None
            required_files = [
                "Install-OpenSearchAgent.ps1",
                "Uninstall-OpenSearchAgent.ps1",
                "Uninstall-VANT-OpenSearch-Agent.exe",
                "vant-opensearch-agent.exe",
                "vant-opensearch-agent-tray.exe",
                "config.yaml",
                "sendheartbeat.exe",
                "sendhearbet.exe",
                "opena_mover.exe",
                "opena_checker.exe",
                "opena_cheker.exe",
            ]
            missing = [name for name in required_files if not (source_dir / name).exists()]
            if missing:
                self._stage_error = "Faltan archivos del payload embebido: " + ", ".join(missing)
                return None

            if self._staged_dir and Path(self._staged_dir).exists():
                shutil.rmtree(self._staged_dir, ignore_errors=True)

            staged_root = Path(tempfile.mkdtemp(prefix="vant_opensearch_agent_setup_"))
            staged_dir = staged_root / "package"
            shutil.copytree(source_dir, staged_dir)

            import yaml

            data = self.build_config_data(mask_secrets=False)
            config_path = staged_dir / "config.yaml"
            config_path.write_text(
                yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
                encoding="utf-8",
            )
            self._staged_dir = staged_dir
            return staged_dir
        except Exception as exc:
            self._stage_error = str(exc)
            return None

    def stage_error(self):
        return self._stage_error

    def install_windows_package(self, package_dir):
        install_script = package_dir / "Install-OpenSearchAgent.ps1"
        if not install_script.exists():
            return False, f"No se encontro el script de instalacion: {install_script}"

        existing_system_install = _system_install_dir().exists()
        requires_elevation = (not _is_admin()) and existing_system_install

        if requires_elevation:
            stdout_path = package_dir / "install-elevated.stdout.log"
            stderr_path = package_dir / "install-elevated.stderr.log"
            install_script_arg = str(install_script).replace("'", "''")
            package_dir_arg = str(package_dir).replace("'", "''")
            stdout_arg = str(stdout_path).replace("'", "''")
            stderr_arg = str(stderr_path).replace("'", "''")
            inner_cmd = (
                "Start-Process powershell.exe "
                f"-Verb RunAs -WorkingDirectory '{package_dir_arg}' -Wait -PassThru "
                f"-RedirectStandardOutput '{stdout_arg}' "
                f"-RedirectStandardError '{stderr_arg}' "
                f"-ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{install_script_arg}\" -RunNow'"
            )

            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", inner_cmd],
                    cwd=str(package_dir),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
                stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
                shell_text = "\n".join(part for part in [result.stdout, result.stderr] if part)
                output = "\n".join(
                    part
                    for part in [
                        "Se detecto una instalacion previa en Program Files. Solicitando elevacion UAC para reinstalar.",
                        stdout_text.strip(),
                        stderr_text.strip(),
                        shell_text.strip() if result.returncode != 0 else "",
                    ]
                    if part
                )
                return result.returncode == 0, output
            except Exception as exc:
                return False, str(exc)

        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(install_script),
            "-RunNow",
        ]
        if not _is_admin():
            cmd.append("-UserMode")
        try:
            result = subprocess.run(
                cmd,
                cwd=str(package_dir),
                capture_output=True,
                text=True,
                check=False,
            )
            output = "\n".join(part for part in [result.stdout, result.stderr] if part)
            if (not _is_admin()) and result.returncode == 0:
                output = "\n".join(
                    part
                    for part in [
                        "Instalacion ejecutada en modo usuario porque el setup no estaba elevado.",
                        output,
                    ]
                    if part
                )
            return result.returncode == 0, output
        except Exception as exc:
            return False, str(exc)


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    wizard = AgentInstallerWizard()
    wizard.resize(820, 540)
    wizard.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
