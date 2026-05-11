import hashlib
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

import requests


DEFAULT_DLP_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".xml",
    ".md",
    ".doc",
    ".docx",
    ".docm",
    ".rtf",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".pdf",
    ".odt",
    ".ods",
    ".odp",
    ".ini",
    ".conf",
    ".cfg",
    ".yaml",
    ".yml",
    ".ps1",
    ".bat",
    ".cmd",
    ".sql",
    ".env",
    ".properties",
}

DEFAULT_DLP_KEYWORDS = [
    {
        "name": "Clasificado",
        "classification": "clasificado",
        "severity": "critical",
        "match_type": "keyword",
        "pattern": "informacion clasificada",
        "tags": ["estado", "clasificado"],
    },
    {
        "name": "Confidential",
        "classification": "confidential",
        "severity": "critical",
        "match_type": "regex",
        "pattern": r"\b(confidential|classified|secret|restricted)\b",
        "tags": ["english", "sensitive"],
    },
    {
        "name": "Secreto",
        "classification": "secreto",
        "severity": "critical",
        "match_type": "keyword",
        "pattern": "secreto",
        "tags": ["estado", "secreto"],
    },
    {
        "name": "Seguridad del Estado",
        "classification": "seguridad_del_estado",
        "severity": "critical",
        "match_type": "keyword",
        "pattern": "seguridad del estado",
        "tags": ["estado", "seguridad"],
    },
    {
        "name": "Restringido",
        "classification": "restringido",
        "severity": "high",
        "match_type": "keyword",
        "pattern": "restringido",
        "tags": ["restringido"],
    },
]


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _state_dir(config_path):
    base = Path(config_path).resolve().parent
    state_dir = base / ".agent_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        state_dir.chmod(0o700)
    except Exception:
        pass
    return state_dir


def _load_state(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _expand_scan_paths(paths):
    expanded = []
    seen = set()
    for path in paths or []:
        value = os.path.expandvars(os.path.expanduser(path))
        if not value:
            continue
        resolved = str(Path(value))
        key = resolved.lower()
        if key in seen:
            continue
        seen.add(key)
        expanded.append(Path(resolved))
    return expanded


def _windows_fixed_drives():
    if os.name != "nt":
        return []
    try:
        import ctypes
        import string

        drive_mask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:
        return []

    drives = []
    for index, letter in enumerate(string.ascii_uppercase):
        if not (drive_mask & (1 << index)):
            continue
        root = f"{letter}:\\"
        try:
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        except Exception:
            continue
        if drive_type in (2, 3):
            drives.append(Path(root))
    return drives


def _windows_scan_roots():
    if os.name != "nt":
        return []

    roots = []
    system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/")
    users_root = Path(f"{system_drive}\\") / "Users"
    public_root = users_root / "Public"
    roots.extend(
        [
            public_root / "Desktop",
            public_root / "Documents",
            public_root / "Downloads",
            public_root / "OneDrive",
        ]
    )

    if users_root.exists():
        for profile in users_root.iterdir():
            if not profile.is_dir():
                continue
            if profile.name.lower() in {"all users", "default", "default user", "public"}:
                continue
            roots.extend(
                [
                    profile / "Desktop",
                    profile / "Documents",
                    profile / "Downloads",
                    profile / "OneDrive",
                    profile / "OneDrive - Personal",
                ]
            )

    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    roots.extend(
        [
            program_data,
            program_data / "VANT",
            Path(os.environ.get("TEMP", r"C:\Temp")),
            Path(os.environ.get("TMP", r"C:\Temp")),
        ]
    )
    roots.extend(_windows_fixed_drives())
    return _expand_scan_paths([str(path) for path in roots])


def _default_paths():
    paths = _windows_scan_roots()
    if not paths:
        paths = _expand_scan_paths([str(Path.home()), str(Path(os.environ.get("TEMP", r"C:\Temp")))])
    return paths


def _default_policy():
    return {
        "code": "aegis-local-shield",
        "name": "Aegis Local Shield",
        "severity": "critical",
        "scan_paths": [str(path) for path in _default_paths()],
        "monitored_extensions": sorted(DEFAULT_DLP_EXTENSIONS),
        "rules": DEFAULT_DLP_KEYWORDS,
    }


def _iter_files(paths, extensions, max_file_size, max_files_per_scan=12000):
    excluded_tokens = (
        "\\$recycle.bin",
        "\\system volume information",
        "\\windows\\winsxs",
        "\\windows\\servicing",
        "\\windows\\softwaredistribution\\download",
        "\\programdata\\package cache",
        "\\programdata\\microsoft\\windows\\wer",
        "\\programdata\\microsoft\\windows defender",
    )
    seen = set()
    yielded = 0
    for base in paths:
        try:
            base_exists = base.exists()
        except Exception:
            continue
        if not base_exists:
            continue
        for root, dirs, files in os.walk(base, topdown=True, onerror=lambda exc: logging.getLogger("vant-siem-agent").warning("walk error: %s", exc)):
            root_path = Path(root)
            root_low = str(root_path).lower()
            if any(token in root_low for token in excluded_tokens):
                continue
            dirs[:] = [
                d
                for d in dirs
                if not any(token in f"{root_low}\\{d.lower()}" for token in excluded_tokens)
            ]
            for name in files:
                path = Path(root) / name
                if str(path) in seen:
                    continue
                seen.add(str(path))
                if extensions and path.suffix.lower() not in extensions:
                    continue
                try:
                    if path.stat().st_size > max_file_size:
                        continue
                except Exception:
                    continue
                yield path
                yielded += 1
                if yielded >= max_files_per_scan:
                    return


def _read_file_text(path):
    suffix = path.suffix.lower()
    try:
        if suffix in {".docx", ".xlsx", ".pptx"}:
            text_parts = []
            with ZipFile(path, "r") as zf:
                total_size = 0
                max_decompressed = 100 * 1024 * 1024
                for member in zf.namelist():
                    if member.endswith(".xml"):
                        info = zf.getinfo(member)
                        total_size += info.file_size
                        if total_size > max_decompressed:
                            break
                        try:
                            text_parts.append(zf.read(member).decode("utf-8", errors="ignore"))
                        except Exception:
                            continue
            return "\n".join(text_parts)
        if suffix == ".pdf":
            try:
                from pypdf import PdfReader

                reader = PdfReader(str(path))
                text_parts = []
                for page in reader.pages[:50]:
                    try:
                        text_parts.append(page.extract_text() or "")
                    except Exception:
                        continue
                text = "\n".join(text_parts).strip()
                if text:
                    return text
            except Exception:
                pass
        if suffix == ".rtf":
            return path.read_text(encoding="utf-8", errors="ignore")
        text = path.read_text(encoding="utf-8", errors="ignore")
        if text.strip():
            return text
        raise ValueError("empty_text")
    except Exception:
        try:
            data = path.read_bytes()
            text = data.decode("utf-8", errors="ignore")
            chunks = [
                chunk.decode("latin1", errors="ignore")
                for chunk in re.findall(rb"[ -~]{6,}", data)
            ]
            if chunks:
                text = "\n".join([text, *chunks[:800]])
            return text
        except Exception:
            return ""


def _sha256(path):
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _file_owner(path):
    if os.name != "nt":
        return ""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "& {param($p) (Get-Acl -LiteralPath $p).Owner}",
             "-p", str(path)],
            capture_output=True, text=True, timeout=8, check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except Exception:
        return ""


def _path_channel(path):
    low = str(path).lower()
    if "\\downloads\\" in low:
        return "downloads"
    if "\\desktop\\" in low:
        return "desktop"
    if "\\documents\\" in low:
        return "documents"
    return "filesystem"


def _metadata_haystack(path, content):
    stat = path.stat() if path.exists() else None
    values = [
        path.name,
        str(path),
        path.suffix.lower(),
        _file_owner(path),
        content,
    ]
    if stat is not None:
        values.extend(
            [
                str(stat.st_size),
                datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            ]
        )
    return "\n".join([item for item in values if item]).lower()


class AegisDlpService:
    module_name = "aegis_dlp"

    def __init__(self, config_path, cfg):
        self.config_path = config_path
        self.cfg = cfg or {}
        self.state_path = _state_dir(config_path) / "aegis_dlp_state.json"
        self.state = _load_state(self.state_path)
        self.remote_config = {}

    def fetch_remote_config(self, control_server, token, agent_id):
        if not control_server:
            return self.remote_config
        try:
            response = requests.post(
                f"{control_server}/api/agent/dlp/config/",
                json={"agent_id": agent_id},
                headers={"Authorization": f"Bearer {token}"} if token else {},
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                self.remote_config = data.get("config") or {}
        except Exception:
            return self.remote_config
        return self.remote_config

    def queue_incidents(self, incidents):
        pending = self.state.get("pending_incidents") or []
        existing = {item.get("fingerprint", "") for item in pending}
        for incident in incidents or []:
            fingerprint = incident.get("fingerprint", "")
            if not fingerprint or fingerprint in existing:
                continue
            pending.append(incident)
            existing.add(fingerprint)
        self.state["pending_incidents"] = pending[-5000:]
        _save_state(self.state_path, self.state)
        return self.state["pending_incidents"]

    def peek_pending_incidents(self):
        return list(self.state.get("pending_incidents") or [])

    def clear_pending_incidents(self):
        self.state["pending_incidents"] = []
        _save_state(self.state_path, self.state)

    def scan(self):
        dlp_cfg = self.cfg.get(self.module_name, {}) or {}
        if not dlp_cfg.get("enabled", True):
            return []

        policies = (self.remote_config or {}).get("policies") or []
        if not policies:
            policies = [_default_policy()]

        rules = []
        scan_paths = []
        default_paths = [str(path) for path in _default_paths()]
        monitored_extensions = set()
        max_file_size_mb = int(dlp_cfg.get("max_file_size_mb", 25) or 25)
        max_files_per_scan = int(dlp_cfg.get("max_files_per_scan", 12000) or 12000)
        max_scan_seconds = int(dlp_cfg.get("max_scan_seconds", 20) or 20)
        for policy in policies:
            scan_paths.extend(policy.get("scan_paths") or [])
            monitored_extensions.update([ext.lower() for ext in (policy.get("monitored_extensions") or [])])
            max_file_size_mb = max(max_file_size_mb, int(policy.get("max_file_size_mb", 10) or 10))
            for rule in policy.get("rules") or []:
                rules.append((policy, rule))

        local_scan_paths = dlp_cfg.get("scan_paths") or []
        if local_scan_paths:
            scan_paths = list(local_scan_paths) + scan_paths

        if not scan_paths:
            scan_paths = default_paths
        else:
            for path in default_paths:
                if path not in scan_paths:
                    scan_paths.append(path)

        monitored_extensions.update([ext.lower() for ext in (dlp_cfg.get("monitored_extensions") or [])])
        monitored_extensions.update(DEFAULT_DLP_EXTENSIONS)
        paths = _expand_scan_paths(scan_paths)
        max_file_size = max_file_size_mb * 1024 * 1024

        incidents = []
        known = set(self.state.get("incident_keys", []))
        scan_cache = self.state.get("scan_cache") or {}
        updated_cache = {}
        started_at = time.monotonic()
        for path in _iter_files(paths, monitored_extensions, max_file_size, max_files_per_scan=max_files_per_scan):
            if max_scan_seconds > 0 and (time.monotonic() - started_at) >= max_scan_seconds:
                break
            try:
                stat = path.stat()
                cache_value = f"{int(stat.st_mtime)}:{stat.st_size}"
            except Exception:
                continue
            cache_key = str(path).lower()
            updated_cache[cache_key] = cache_value
            if scan_cache.get(cache_key) == cache_value:
                continue
            content = _read_file_text(path)
            haystack = _metadata_haystack(path, content)
            if not haystack.strip():
                continue
            for policy, rule in rules:
                pattern = (rule.get("pattern") or "").strip()
                if not pattern:
                    continue
                matched_terms = []
                match_type = (rule.get("match_type") or "keyword").strip().lower()
                if match_type == "regex":
                    if re.search(pattern, haystack, flags=re.IGNORECASE):
                        matched_terms.append(pattern)
                elif match_type == "metadata":
                    if pattern.lower() in haystack:
                        matched_terms.append(pattern)
                else:
                    if pattern.lower() in haystack:
                        matched_terms.append(pattern)
                if not matched_terms:
                    continue

                file_hash = _sha256(path)
                incident_key = hashlib.sha256(
                    f"{file_hash}|{path}|{policy.get('code')}|{rule.get('name')}".encode("utf-8")
                ).hexdigest()
                if incident_key in known:
                    continue
                known.add(incident_key)
                incidents.append(
                    {
                        "fingerprint": incident_key,
                        "policy_code": policy.get("code", ""),
                        "rule_name": rule.get("name", ""),
                        "classification": rule.get("classification") or policy.get("code", ""),
                        "severity": rule.get("severity") or policy.get("severity", "high"),
                        "file_name": path.name,
                        "file_path": str(path),
                        "file_hash": file_hash,
                        "actor": _file_owner(path),
                        "channel": _path_channel(path),
                        "status": "open",
                        "detected_at": _utc_now(),
                        "summary": f"Coincidencia DLP en {path.name}",
                        "matched_keywords": matched_terms,
                        "metadata": {
                            "size": path.stat().st_size if path.exists() else 0,
                            "suffix": path.suffix.lower(),
                            "created_at": datetime.fromtimestamp(path.stat().st_ctime, tz=timezone.utc).isoformat() if path.exists() else "",
                            "modified_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat() if path.exists() else "",
                        },
                    }
                )
                if len(incidents) >= 25:
                    self.queue_incidents(incidents)
                    incidents = []
        self.queue_incidents(incidents)
        self.state["incident_keys"] = sorted(list(known))[-5000:]
        self.state["scan_cache"] = dict(list(updated_cache.items())[-25000:])
        _save_state(self.state_path, self.state)
        return incidents
