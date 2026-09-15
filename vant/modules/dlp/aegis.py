"""
VANT-SIEM Aegis DLP Engine v2.0 - Enterprise Data Loss Prevention

Real-time + batch file content analysis for sensitive data detection.
Supports: PDF, DOCX/XLSX/PPTX, ODF (LibreOffice), legacy OLE, RTF, EML/MSG,
          CSV, SQL, TXT, archives (ZIP/TAR/GZ/BZ2), encrypted file detection.

Features:
  - Cuban PII: credit cards (9xxx series), identity cards (11 digits), phones (+53)
  - Credential/secret detection: API keys, passwords, private keys, connection strings
  - Quarantine: move flagged files to restricted directory + alert bus
  - Context window: +/-200 chars around each match for analyst review
  - Match scope: content / metadata / filename / all
  - Archive scanning: ZIP/TAR/GZ/BZ2 (one level deep)
  - Encrypted file detection: password ZIP, encrypted PDF, protected Office
"""
import base64
import hashlib
import io
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tarfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile, BadZipFile

from vant.utils import run_hidden

import requests

logger = logging.getLogger("vant-agent.dlp")

# ============================================================================
#  CONSTANTS
# ============================================================================

DEFAULT_DLP_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".md",
    ".doc", ".docx", ".docm", ".rtf",
    ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm",
    ".pdf",
    ".odt", ".ods", ".odp",
    ".ini", ".conf", ".cfg", ".yaml", ".yml",
    ".ps1", ".bat", ".cmd", ".sql",
    ".env", ".properties",
    ".html", ".htm", ".eml", ".msg",
    ".zip", ".tar", ".gz", ".bz2", ".tgz",
}

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".bz2", ".tgz"}

DEFAULT_DLP_KEYWORDS = [
    {"name": "Clasificado", "classification": "clasificado", "severity": "critical",
     "match_type": "keyword", "match_scope": "all",
     "pattern": "informacion clasificada",
     "tags": ["estado", "clasificado"]},
    {"name": "Confidential", "classification": "confidential", "severity": "critical",
     "match_type": "regex", "match_scope": "all",
     "pattern": r"\b(confidential|classified|secret|restricted)\b",
     "tags": ["english", "sensitive"]},
    {"name": "Secreto", "classification": "secreto", "severity": "critical",
     "match_type": "keyword", "match_scope": "all",
     "pattern": "secreto",
     "tags": ["estado", "secreto"]},
    {"name": "Seguridad del Estado", "classification": "seguridad_del_estado", "severity": "critical",
     "match_type": "keyword", "match_scope": "all",
     "pattern": "seguridad del estado",
     "tags": ["estado", "seguridad"]},
    {"name": "Restringido", "classification": "restringido", "severity": "high",
     "match_type": "keyword", "match_scope": "all",
     "pattern": "restringido",
     "tags": ["restringido"]},
]

ENTERPRISE_PII_RULES = [
    {"name": "Tarjeta de credito cubana (9xxx)", "classification": "PII-Financial",
     "severity": "critical", "match_type": "regex", "match_scope": "content",
     "pattern": r"\b9\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
     "tags": ["tarjeta", "credito", "cuba", "financiero"]},
    {"name": "Tarjeta de credito (Visa/MC/Amex)", "classification": "PII-Financial",
     "severity": "high", "match_type": "regex", "match_scope": "content",
     "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-9][0-9]{14}|3[47][0-9]{13})\b",
     "tags": ["tarjeta", "credito"]},
    {"name": "Carnet de identidad cubano", "classification": "PII-Identity",
     "severity": "critical", "match_type": "regex", "match_scope": "content",
     "pattern": r"\b\d{4}\s?\d{4}\s?\d{3}\b",
     "tags": ["carnet", "identidad", "cuba"]},
    {"name": "Telefono cubano (+53)", "classification": "PII-Phone",
     "severity": "high", "match_type": "regex", "match_scope": "content",
     "pattern": r"\+?53[\s\-]?[5-9]\d{7,8}\b",
     "tags": ["telefono", "cuba", "movil"]},
]

ENTERPRISE_SECRET_RULES = [
    {"name": "Clave privada / Private Key", "classification": "Secret-Credential",
     "severity": "critical", "match_type": "regex", "match_scope": "content",
     "pattern": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----",
     "tags": ["clave", "privada", "criptografia"]},
    {"name": "Password hardcoded", "classification": "Secret-Credential",
     "severity": "high", "match_type": "regex", "match_scope": "content",
     "pattern": r"(?:password|passwd|pwd|contraseña|clave)\s*[=:]\s*['\"]?[^\s'\"]{4,}",
     "tags": ["password", "credencial"]},
    {"name": "API Key / Token", "classification": "Secret-Credential",
     "severity": "high", "match_type": "regex", "match_scope": "content",
     "pattern": r"(?:api[_\-]?key|apikey|token|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_\.]{16,}",
     "tags": ["api", "token", "clave"]},
    {"name": "AWS Access Key", "classification": "Secret-Credential",
     "severity": "critical", "match_type": "regex", "match_scope": "content",
     "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
     "tags": ["aws", "cloud"]},
    {"name": "Connection String", "classification": "Secret-Credential",
     "severity": "high", "match_type": "regex", "match_scope": "content",
     "pattern": r"(?:jdbc|mongodb|redis|mysql|postgres|amqp)://[^\s'\"]+",
     "tags": ["conexion", "base_datos"]},
]

ALL_BUILTIN_RULES = DEFAULT_DLP_KEYWORDS + ENTERPRISE_PII_RULES + ENTERPRISE_SECRET_RULES

QUARANTINE_DIR = "/var/quarantine/vant-dlp"
CONTEXT_WINDOW = 200
MAX_ARCHIVE_ENTRIES = 200
MAX_ARCHIVE_SIZE_MB = 100


# ============================================================================
#  STATE MANAGEMENT
# ============================================================================

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


# ============================================================================
#  PATH UTILITIES
# ============================================================================

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
    return _expand_scan_paths([str(p) for p in _windows_fixed_drives()])


def _linux_scan_roots():
    if os.name == "nt":
        return []
    roots = [Path("/")]
    try:
        result = subprocess.run(
            ["findmnt", "-rno", "TARGET,SOURCE,FSTYPE"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("/dev/"):
                mount = parts[0]
                if mount not in ("/", "/proc", "/sys", "/dev", "/run", "/boot/efi"):
                    roots.append(Path(mount))
    except Exception:
        pass
    return _expand_scan_paths([str(p) for p in roots])


def _default_paths():
    if os.name == "nt":
        paths = _windows_scan_roots()
    else:
        paths = _linux_scan_roots()
    if not paths:
        paths = _expand_scan_paths([str(Path.home()), "/tmp"])
    return paths


def _default_policy():
    return {
        "code": "aegis-local-shield",
        "name": "Aegis Local Shield",
        "severity": "critical",
        "scan_paths": [str(p) for p in _default_paths()],
        "monitored_extensions": sorted(DEFAULT_DLP_EXTENSIONS),
        "rules": ALL_BUILTIN_RULES,
    }


def _iter_files(paths, extensions, max_file_size, max_files_per_scan=12000):
    is_win = os.name == "nt"
    win_excluded = (
        "\\$recycle.bin", "\\system volume information", "\\windows\\winsxs",
        "\\windows\\servicing", "\\windows\\softwaredistribution\\download",
        "\\programdata\\package cache", "\\programdata\\microsoft\\windows\\wer",
        "\\programdata\\microsoft\\windows defender",
    )
    linux_excluded = (
        "/proc", "/sys", "/dev", "/run", "/lost+found",
        "/.snapshots", "/var/cache", "/var/lib/docker", "/snap",
        "/usr/share/doc", "/usr/share/man", "/usr/share/info",
        "/usr/share/groff", "/usr/share/lintian", "/usr/share/linda",
        "/usr/lib", "/usr/libexec", "/usr/src", "/usr/include",
        "/etc", "/boot",
        "/var/lib", "/var/spool", "/var/backups",
        QUARANTINE_DIR,
    )
    seen = set()
    yielded = 0
    for base in paths:
        try:
            if not base.exists():
                continue
        except Exception:
            continue
        for root, dirs, files in os.walk(base, topdown=True, onerror=lambda exc: logger.warning("walk error: %s", exc)):
            root_low = str(Path(root)).lower()
            excl = win_excluded if is_win else linux_excluded
            if any(t in root_low for t in excl):
                continue
            sep = "\\" if is_win else "/"
            dirs[:] = [d for d in dirs if not any(t in f"{root_low}{sep}{d.lower()}" for t in excl)]
            for name in files:
                path = Path(root) / name
                if str(path) in seen:
                    continue
                seen.add(str(path))
                if path.name.endswith(".dlp.json"):
                    continue
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



# ============================================================================
#  FILE FORMAT TEXT EXTRACTION
# ============================================================================

def _read_docx_text(path):
    """Extract text + metadata from DOCX/DOCM. Returns (text, metadata_dict)."""
    try:
        from docx import Document
        doc = Document(str(path))
        parts = []
        for p in doc.paragraphs:
            if p.text.strip():
                parts.append(p.text)
        for section in doc.sections:
            if section.header:
                for p in section.header.paragraphs:
                    if p.text.strip():
                        parts.append(p.text)
            if section.footer:
                for p in section.footer.paragraphs:
                    if p.text.strip():
                        parts.append(p.text)
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.text.strip():
                        parts.append(cell.text)
        try:
            for comment in doc.comments:
                if comment.text.strip():
                    parts.append(comment.text)
        except Exception:
            pass
        props = doc.core_properties
        meta = {}
        for attr in ("author", "last_modified_by", "title", "subject", "keywords",
                      "category", "comments", "created", "modified"):
            val = getattr(props, attr, None)
            if val:
                parts.append(str(val))
                meta[attr] = str(val)
        return "\n".join(parts), meta
    except Exception:
        return "", {}


def _read_xlsx_text(path):
    """Extract text + metadata from XLSX/XLSM. Returns (text, metadata_dict)."""
    try:
        from openpyxl import load_workbook
        wb = load_workbook(str(path), data_only=True, read_only=True)
        parts = []
        meta = {"sheet_count": len(wb.sheetnames), "sheets": wb.sheetnames[:20]}
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            parts.append(sheet_name)
            for row in ws.iter_rows(values_only=True):
                for cell in row:
                    if cell is not None:
                        parts.append(str(cell))
        wb.close()
        return "\n".join(parts), meta
    except Exception:
        return "", {}


def _read_pptx_text(path):
    """Extract text from PPTX/PPTM. Returns (text, metadata_dict)."""
    try:
        from pptx import Presentation
        prs = Presentation(str(path))
        parts = []
        slide_count = 0
        for slide in prs.slides:
            slide_count += 1
            for shape in slide.shapes:
                if shape.has_text_frame:
                    for p in shape.text_frame.paragraphs:
                        if p.text.strip():
                            parts.append(p.text)
                if shape.has_table:
                    for row in shape.table.rows:
                        for cell in row.cells:
                            if cell.text.strip():
                                parts.append(cell.text)
        return "\n".join(parts), {"slide_count": slide_count}
    except Exception:
        return "", {}


def _read_odf_text(path):
    """Extract text from ODF (ODT/ODS/ODP). Returns (text, metadata_dict)."""
    suffix = path.suffix.lower()
    try:
        from odf.opendocument import load
        doc = load(str(path))
        parts = []
        if suffix == ".odt":
            from odf.text import P
            for el in doc.getElementsByType(P):
                txt = "".join(n.data for n in el.childNodes if hasattr(n, "data"))
                if txt.strip():
                    parts.append(txt)
        elif suffix == ".ods":
            from odf.table import Table, TableCell
            from odf.text import P as TextP
            for table in doc.getElementsByType(Table):
                for cell in table.getElementsByType(TableCell):
                    for p in cell.getElementsByType(TextP):
                        txt = "".join(n.data for n in p.childNodes if hasattr(n, "data"))
                        if txt.strip():
                            parts.append(txt)
        elif suffix == ".odp":
            from odf.draw import Page, Frame
            from odf.text import P as TextP
            for page in doc.getElementsByType(Page):
                for frame in page.getElementsByType(Frame):
                    for p in frame.getElementsByType(TextP):
                        txt = "".join(n.data for n in p.childNodes if hasattr(n, "data"))
                        if txt.strip():
                            parts.append(txt)
        return "\n".join(parts), {"format": "odf", "type": suffix.lstrip(".")}
    except Exception:
        return "", {}


def _read_ole_text(path):
    """Extract text from legacy OLE (DOC/XLS/PPT). Returns (text, metadata_dict)."""
    try:
        import olefile
        if not olefile.isOleFile(str(path)):
            return "", {}
        ole = olefile.OleFileIO(str(path))
        parts = []
        meta = {"format": "ole"}
        try:
            mi = ole.get_metadata()
            for attr in ("author", "title", "subject", "keywords"):
                val = getattr(mi, attr, None)
                if val:
                    tv = val.decode("utf-8", errors="ignore") if isinstance(val, bytes) else str(val)
                    if tv.strip():
                        parts.append(tv)
                        meta[attr] = tv
        except Exception:
            pass
        for stream in ole.listdir():
            try:
                data = ole.openstream("/".join(stream)).read()
                text = data.decode("utf-8", errors="ignore")
                if text.strip():
                    parts.append(text)
            except Exception:
                pass
        ole.close()
        return "\n".join(parts), meta
    except Exception:
        return "", {}


def _read_pdf_text(path, max_pages=None):
    """Extract text + metadata from PDF. Returns (text, metadata_dict)."""
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        parts = []
        meta = {}
        if reader.metadata:
            for attr in ("author", "creator", "producer", "title", "subject", "keywords"):
                val = reader.metadata.get(attr)
                if val:
                    parts.append(f"{attr}: {val}")
                    meta[attr] = str(val)
        meta["page_count"] = len(reader.pages)
        meta["encrypted"] = reader.is_encrypted
        if reader.is_encrypted:
            meta["scan_note"] = "PDF encrypted - content may not be fully extractable"
        pages_to_process = reader.pages if max_pages is None else reader.pages[:max_pages]
        for page in pages_to_process:
            try:
                text = page.extract_text()
                if text and text.strip():
                    parts.append(text.strip())
            except Exception:
                continue
        return "\n".join(parts), meta
    except Exception:
        return "", {}


def _read_msg_text(path):
    """Extract text from Outlook .msg via olefile. Returns (text, metadata_dict)."""
    try:
        import olefile
        if not olefile.isOleFile(str(path)):
            return "", {}
        ole = olefile.OleFileIO(str(path))
        parts = []
        meta = {"format": "msg", "source": "outlook"}

        def _rs(name):
            try:
                data = ole.openstream(name).read()
                if not data:
                    return ""
                if len(data) >= 4 and data[0:4] in (b"\x02\x00\x00\x00", b"\x01\x00\x00\x00"):
                    return data.decode("utf-16-le", errors="ignore").strip()
                return data.decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""

        subject = _rs("__substg1.0_0037001F")
        if subject:
            parts.append(f"Subject: {subject}")
            meta["subject"] = subject
        body = _rs("__substg1.0_1000001F")
        if body:
            parts.append(body)
        for tag in ("__substg1.0_0065001F", "__substg1.0_0076001F"):
            val = _rs(tag)
            if val:
                parts.append(f"Email: {val}")
        ole.close()
        return "\n".join(parts), meta
    except Exception:
        return "", {}


def _strip_rtf(raw_text):
    """Strip RTF markup to extract readable text."""
    text = re.sub(r"\\[a-z]+\d*\s?", " ", raw_text)
    text = re.sub(r"\{[^}]*\}", " ", text)
    text = re.sub(r"\\['\"]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _read_email_text(path):
    """Extract text from EML. Returns (text, metadata_dict)."""
    try:
        import email
        with open(path, "rb") as f:
            msg = email.message_from_binary_file(f)
        parts = []
        meta = {"format": "eml"}
        for header in ("Subject", "From", "To", "Cc", "Bcc", "Date"):
            val = msg[header]
            if val:
                parts.append(f"{header}: {val}")
                meta[header.lower()] = val
        for part in msg.walk():
            if part.get_content_type().startswith("text/"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
        return "\n".join(parts), meta
    except Exception:
        return "", {}


def _read_archive_text(path):
    """Extract text from archives (ZIP/TAR/GZ/BZ2). Returns (text, metadata_dict)."""
    suffix = path.suffix.lower()
    parts = []
    meta = {"format": "archive", "type": suffix.lstrip("."), "entries": []}
    text_exts = {
        ".txt", ".log", ".csv", ".json", ".xml", ".md", ".sql",
        ".yaml", ".yml", ".ini", ".conf", ".cfg", ".env", ".properties",
        ".html", ".htm", ".py", ".sh", ".ps1", ".bat", ".cmd",
    }
    doc_exts = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".pdf", ".eml"}

    if suffix == ".zip":
        try:
            with ZipFile(str(path), "r") as zf:
                entries = zf.namelist()
                meta["total_entries"] = len(entries)
                count = 0
                for entry_name in entries[:MAX_ARCHIVE_ENTRIES]:
                    ext = Path(entry_name).suffix.lower()
                    if ext not in text_exts and ext not in doc_exts:
                        continue
                    try:
                        with zf.open(entry_name) as ef:
                            raw = ef.read(10 * 1024 * 1024)
                        if ext in doc_exts:
                            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                                tmp.write(raw)
                                tmp_path = Path(tmp.name)
                            try:
                                t, _ = _read_file_content(tmp_path)
                                if t:
                                    parts.append(t)
                            finally:
                                tmp_path.unlink(missing_ok=True)
                        else:
                            text = raw.decode("utf-8", errors="ignore")
                            if text.strip():
                                parts.append(text)
                        count += 1
                    except Exception:
                        continue
                meta["entries"] = entries[:50]
                meta["scanned_entries"] = count
        except BadZipFile:
            meta["error"] = "corrupt_zip"
        except Exception as e:
            meta["error"] = str(e)[:200]
    else:
        try:
            with tarfile.open(str(path), "r:*") as tf:
                count = 0
                for member in tf.getmembers()[:MAX_ARCHIVE_ENTRIES]:
                    if not member.isfile():
                        continue
                    ext = Path(member.name).suffix.lower()
                    if ext not in text_exts:
                        continue
                    try:
                        fobj = tf.extractfile(member)
                        if fobj:
                            raw = fobj.read(10 * 1024 * 1024)
                            text = raw.decode("utf-8", errors="ignore")
                            if text.strip():
                                parts.append(text)
                            count += 1
                    except Exception:
                        continue
                meta["entries"] = [m.name for m in tf.getmembers()[:50]]
                meta["scanned_entries"] = count
        except Exception as e:
            meta["error"] = str(e)[:200]

    return "\n".join(parts), meta


def _detect_encrypted(path):
    """Detect encrypted/password-protected files. Returns (is_encrypted, enc_type)."""
    suffix = path.suffix.lower()
    if suffix == ".zip":
        try:
            with ZipFile(str(path), "r") as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True, "zip_password"
        except Exception:
            pass
    elif suffix == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(str(path))
            if reader.is_encrypted:
                return True, "pdf_encrypted"
        except Exception:
            pass
    elif suffix in {".docx", ".xlsx", ".pptx"}:
        try:
            if suffix == ".docx":
                from docx import Document
                Document(str(path))
            elif suffix == ".xlsx":
                from openpyxl import load_workbook
                load_workbook(str(path))
            else:
                from pptx import Presentation
                Presentation(str(path))
        except Exception as e:
            err = str(e).lower()
            if "password" in err or "encrypt" in err or "decrypt" in err:
                return True, f"{suffix.lstrip('.')}_encrypted"
    return False, ""


# ============================================================================
#  UNIFIED FILE READING
# ============================================================================

def _read_file_content(path):
    """Read file content and metadata. Returns (content_text, metadata_dict)."""
    import tempfile
    suffix = path.suffix.lower()
    try:
        if suffix in {".docx", ".docm"}:
            return _read_docx_text(path)
        elif suffix in {".xlsx", ".xlsm"}:
            return _read_xlsx_text(path)
        elif suffix in {".pptx", ".pptm"}:
            return _read_pptx_text(path)
        elif suffix in {".odt", ".ods", ".odp"}:
            return _read_odf_text(path)
        elif suffix in {".doc", ".xls", ".ppt"}:
            return _read_ole_text(path)
        elif suffix == ".pdf":
            return _read_pdf_text(path)
        elif suffix == ".rtf":
            raw = path.read_text(encoding="utf-8", errors="ignore")
            return _strip_rtf(raw), {"format": "rtf"}
        elif suffix == ".msg":
            return _read_msg_text(path)
        elif suffix == ".eml":
            return _read_email_text(path)
        elif suffix in ARCHIVE_EXTENSIONS:
            return _read_archive_text(path)
        else:
            text = path.read_text(encoding="utf-8", errors="ignore")
            return text, {}
    except Exception:
        pass
    try:
        data = path.read_bytes()
        text = data.decode("utf-8", errors="ignore")
        chunks = [
            chunk.decode("latin1", errors="ignore")
            for chunk in re.findall(rb"[ -~]{6,}", data)
        ]
        if chunks:
            text = "\n".join([text, *chunks[:800]])
        return text, {}
    except Exception:
        return "", ""



# ============================================================================
#  HASHING, METADATA, CONTEXT
# ============================================================================

def _sha256(path):
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _file_owner(path):
    if os.name == "nt":
        try:
            proc = run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "& {param($p) (Get-Acl -LiteralPath $p).Owner}", "-p", str(path)],
                capture_output=True, text=True, timeout=8, check=False,
            )
            return proc.stdout.strip() if proc.returncode == 0 else ""
        except Exception:
            return ""
    try:
        import pwd
        return pwd.getpwuid(path.stat().st_uid).pw_name
    except Exception:
        return ""


def _path_channel(path):
    low = str(path).lower()
    if "\\downloads\\" in low or "/downloads/" in low:
        return "downloads"
    if "\\desktop\\" in low or "/desktop/" in low:
        return "desktop"
    if "\\documents\\" in low or "/documents/" in low:
        return "documents"
    return "filesystem"


def _metadata_haystack(path, content, file_meta=None):
    """Build searchable haystack from content + metadata."""
    stat = path.stat() if path.exists() else None
    values = [path.name, str(path), path.suffix.lower(), _file_owner(path), content]
    if file_meta:
        for key in ("author", "creator", "title", "subject", "keywords", "comments"):
            val = file_meta.get(key)
            if val:
                values.append(str(val))
    if stat is not None:
        values.extend([
            str(stat.st_size),
            datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        ])
    return "\n".join(v for v in values if v).lower()


def _extract_context(text, match_start, match_end, window=CONTEXT_WINDOW):
    """Extract context window around a match."""
    if not text:
        return ""
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    ctx = text[start:end].strip()
    if start > 0:
        ctx = "..." + ctx
    if end < len(text):
        ctx = ctx + "..."
    return ctx


# ============================================================================
#  QUARANTINE
# ============================================================================

def _quarantine_file(path, incident):
    """Move file to quarantine directory. Returns True on success."""
    try:
        qdir = Path(QUARANTINE_DIR)
        qdir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^\w\.\-]", "_", path.name)
        dest = qdir / f"{ts}_{safe_name}"
        shutil.move(str(path), str(dest))
        meta = {
            "original_path": str(path),
            "quarantined_at": _utc_now(),
            "fingerprint": incident.get("fingerprint", ""),
            "policy_code": incident.get("policy_code", ""),
            "rule_name": incident.get("rule_name", ""),
            "classification": incident.get("classification", ""),
            "severity": incident.get("severity", ""),
            "file_hash": incident.get("file_hash", ""),
            "actor": incident.get("actor", ""),
        }
        meta_file = dest.with_suffix(dest.suffix + ".dlp.json")
        meta_file.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("quarantined %s -> %s", path, dest)
        return True
    except Exception as e:
        logger.warning("quarantine failed for %s: %s", path, e)
        return False


# ============================================================================
#  FILESYSTEM WATCHERS
# ============================================================================

class InotifyWatcher:
    """Real-time filesystem watcher using Linux inotify (no pip dependencies)."""

    IN_MODIFY = 0x00000002
    IN_CREATE = 0x00000100
    IN_MOVED_TO = 0x00000080
    IN_DELETE = 0x00000400
    IN_Q_OVERFLOW = 0x00004000
    IN_IS_DIR = 0x40000000
    EVENTS_MASK = IN_MODIFY | IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_Q_OVERFLOW

    def __init__(self, scan_paths, extensions, on_event_callback=None):
        self.logger = logging.getLogger("vant-agent.dlp.inotify")
        self.scan_paths = scan_paths
        self.extensions = extensions
        self.on_event = on_event_callback
        self._fd = -1
        self._wd_map = {}
        self._running = False
        self._thread = None
        self._new_files_queue = []
        self._lock = threading.Lock()

    def _init_inotify(self):
        try:
            import ctypes
            import ctypes.util
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return False
            libc = ctypes.CDLL(libc_path, use_errno=True)
            self._inotify_init = libc.inotify_init
            self._inotify_init.restype = ctypes.c_int
            self._inotify_add_watch = libc.inotify_add_watch
            self._inotify_add_watch.restype = ctypes.c_int
            self._inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            self._inotify_rm_watch = libc.inotify_rm_watch
            self._inotify_rm_watch.restype = ctypes.c_int
            self._inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
            self._fd = self._inotify_init()
            return self._fd >= 0
        except Exception as exc:
            self.logger.warning("inotify init failed: %s", exc)
            return False

    def _add_watch_recursive(self, path, max_depth=4, depth=0):
        if depth > max_depth:
            return
        try:
            p = Path(path)
            if not p.exists() or not p.is_dir():
                return
            wd = self._inotify_add_watch(self._fd, str(path).encode("utf-8"), self.EVENTS_MASK)
            if wd >= 0:
                self._wd_map[wd] = str(path)
        except Exception:
            return
        if depth < max_depth:
            try:
                for child in Path(path).iterdir():
                    if child.is_dir() and not child.name.startswith("."):
                        self._add_watch_recursive(child, max_depth, depth + 1)
            except Exception:
                pass

    def start(self):
        if os.name == "nt" or not self._init_inotify():
            return False
        for path in self.scan_paths:
            self._add_watch_recursive(path, max_depth=4)
        self._running = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True, name="dlp-inotify")
        self._thread.start()
        self.logger.info("inotify started on %d directories", len(self._wd_map))
        return True

    def stop(self):
        self._running = False
        if self._fd >= 0:
            for wd in self._wd_map:
                try:
                    self._inotify_rm_watch(self._fd, wd)
                except Exception:
                    pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = -1
        self._wd_map.clear()

    def _watch_loop(self):
        import select
        while self._running:
            try:
                ready, _, _ = select.select([self._fd], [], [], 2.0)
                if not ready:
                    continue
                data = os.read(self._fd, 65536)
                offset = 0
                while offset < len(data):
                    wd, mask, cookie, name_len = struct.unpack("iIII", data[offset:offset + 16])
                    offset += 16
                    name = data[offset:offset + name_len].rstrip(b"\x00").decode("utf-8", errors="ignore")
                    offset += name_len
                    if mask & self.IN_Q_OVERFLOW or mask & self.IN_IS_DIR or not name:
                        continue
                    ext = Path(name).suffix.lower()
                    if self.extensions and ext not in self.extensions:
                        continue
                    dir_path = self._wd_map.get(wd, "")
                    if dir_path:
                        full_path = os.path.join(dir_path, name)
                        with self._lock:
                            self._new_files_queue.append(full_path)
                        if self.on_event:
                            try:
                                self.on_event(full_path, mask)
                            except Exception:
                                pass
            except Exception as exc:
                if self._running:
                    self.logger.warning("inotify read error: %s", exc)
                time.sleep(1)

    def get_new_files(self):
        with self._lock:
            files = list(self._new_files_queue)
            self._new_files_queue.clear()
        return files


class WindowsFileWatcher:
    """Fallback file watcher for Windows using polling."""

    def __init__(self, scan_paths, extensions, on_event_callback=None):
        self.logger = logging.getLogger("vant-agent.dlp.winwatch")
        self.scan_paths = scan_paths
        self.extensions = extensions
        self.on_event = on_event_callback
        self._running = False
        self._thread = None
        self._new_files_queue = []
        self._lock = threading.Lock()
        self._snapshot = {}

    def _take_snapshot(self):
        snapshot = {}
        for base in self.scan_paths:
            try:
                for root, dirs, files in os.walk(base, topdown=True, onerror=lambda e: None):
                    for name in files:
                        ext = Path(name).suffix.lower()
                        if self.extensions and ext not in self.extensions:
                            continue
                        fp = os.path.join(root, name)
                        try:
                            st = os.stat(fp)
                            snapshot[fp] = (int(st.st_mtime), st.st_size)
                        except Exception:
                            pass
            except Exception:
                pass
        return snapshot

    def start(self):
        self._snapshot = self._take_snapshot()
        self._running = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True, name="dlp-winwatch")
        self._thread.start()
        self.logger.info("Windows watcher started (polling 10s)")
        return True

    def stop(self):
        self._running = False

    def _watch_loop(self):
        while self._running:
            time.sleep(10)
            try:
                new_snap = self._take_snapshot()
                for fp, (mtime, size) in new_snap.items():
                    if fp not in self._snapshot or self._snapshot[fp] != (mtime, size):
                        with self._lock:
                            self._new_files_queue.append(fp)
                        if self.on_event:
                            try:
                                self.on_event(fp, 0x00000100)
                            except Exception:
                                pass
                self._snapshot = new_snap
            except Exception as exc:
                if self._running:
                    self.logger.warning("winwatch error: %s", exc)

    def get_new_files(self):
        with self._lock:
            files = list(self._new_files_queue)
            self._new_files_queue.clear()
        return files



# ============================================================================
#  MAIN DLP SERVICE
# ============================================================================

class AegisDlpService:
    module_name = "aegis_dlp"

    def __init__(self, config_path, cfg):
        self.config_path = config_path
        self.cfg = cfg or {}
        self.state_path = _state_dir(config_path) / "aegis_dlp_state.json"
        self.state = _load_state(self.state_path)
        self.remote_config = {}
        self._init_drive_state()
        self._watcher = None
        self.logger = logging.getLogger("vant-agent.dlp.service")

    def _init_drive_state(self):
        if os.name == "nt":
            known = set(self.state.get("known_drives") or [])
            if not known:
                current = {str(d).lower() for d in _windows_fixed_drives()}
                self.state["known_drives"] = sorted(current)
        else:
            known = set(self.state.get("known_mounts") or [])
            if not known:
                current = set()
                try:
                    result = subprocess.run(["mount", "-l"], capture_output=True, text=True, timeout=10, check=False)
                    for line in result.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].startswith("/dev/"):
                            current.add(parts[2].lower())
                except Exception:
                    pass
                self.state["known_mounts"] = sorted(current)

    def detect_new_drives(self):
        if os.name == "nt":
            known = set(self.state.get("known_drives") or [])
            current = {str(d).lower() for d in _windows_fixed_drives()}
            new_drives = current - known
            self.state["known_drives"] = sorted(current)
            if new_drives:
                _save_state(self.state_path, self.state)
            return [Path(d) for d in new_drives]
        else:
            known = set(self.state.get("known_mounts") or [])
            current = set()
            try:
                result = subprocess.run(["mount", "-l"], capture_output=True, text=True, timeout=10, check=False)
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].startswith("/dev/"):
                        current.add(parts[2].lower())
            except Exception:
                pass
            new_mounts = current - known
            self.state["known_mounts"] = sorted(current)
            if new_mounts:
                _save_state(self.state_path, self.state)
            return [Path(d) for d in new_mounts]

    def start_watcher(self, scan_paths, extensions):
        if self._watcher is not None:
            return
        def _on_event(fp, mask):
            self.logger.debug("file event: %s mask=0x%x", fp, mask)
        if os.name == "nt":
            self._watcher = WindowsFileWatcher(scan_paths, extensions, _on_event)
        else:
            self._watcher = InotifyWatcher(scan_paths, extensions, _on_event)
        self._watcher.start()

    def stop_watcher(self):
        if self._watcher:
            self._watcher.stop()
            self._watcher = None

    def get_realtime_events(self):
        if not self._watcher:
            return []
        return self._watcher.get_new_files()

    def fetch_remote_config(self, control_server, token, agent_id):
        if not control_server:
            return self.remote_config
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            url = f"{control_server.rstrip('/')}/api/agent/dlp/config/"
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                policies = data.get("policies") or []
                self.remote_config = {"policies": policies}
                self.logger.info("fetched %d remote DLP policies", len(policies))
        except Exception as e:
            self.logger.debug("fetch_remote_config failed: %s", e)
        return self.remote_config

    def submit_threats(self, server_url, token, agent_id, incidents):
        if not server_url or not incidents:
            return None
        max_upload = int(self.cfg.get(self.module_name, {}).get("max_upload_size_mb", 10) or 10)
        max_upload_bytes = max_upload * 1024 * 1024
        enriched = []
        for inc in incidents:
            item = dict(inc)
            file_path = item.get("file_path", "")
            if file_path and max_upload_bytes > 0:
                try:
                    p = Path(file_path)
                    if p.exists() and p.stat().st_size <= max_upload_bytes:
                        item["file_content_base64"] = base64.b64encode(p.read_bytes()).decode("ascii")
                except Exception:
                    pass
            enriched.append(item)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"} if token else {}
        try:
            response = requests.post(
                f"{server_url.rstrip('/')}/api/agent/dlp/threats/",
                json={"agent_id": agent_id, "incidents": enriched},
                headers=headers,
                timeout=120,
            )
            return response
        except Exception:
            return None

    def queue_incidents(self, incidents):
        pending = self.state.get("pending_incidents") or []
        existing = {item.get("fingerprint", "") for item in pending}
        for incident in incidents or []:
            fp = incident.get("fingerprint", "")
            if not fp or fp in existing:
                continue
            pending.append(incident)
            existing.add(fp)
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
        default_paths = [str(p) for p in _default_paths()]
        monitored_extensions = set()
        max_file_size_mb = int(dlp_cfg.get("max_file_size_mb", 25) or 25)
        max_files_per_scan = int(dlp_cfg.get("max_files_per_scan", 12000) or 12000)
        max_scan_seconds = int(dlp_cfg.get("max_scan_seconds", 0) or 0)
        realtime_enabled = dlp_cfg.get("realtime_enabled", True)
        quarantine_enabled = dlp_cfg.get("quarantine_enabled", True)

        for policy in policies:
            scan_mode = policy.get("scan_mode", "all")
            if scan_mode == "all":
                scan_paths = [str(p) for p in _default_paths()]
            else:
                scan_paths.extend(policy.get("scan_paths") or [])
            monitored_extensions.update(e.lower() for e in (policy.get("monitored_extensions") or []))
            max_file_size_mb = max(max_file_size_mb, int(policy.get("max_file_size_mb", 10) or 10))
            for rule in policy.get("rules") or []:
                rules.append((policy, rule))

        new_drives = self.detect_new_drives()
        if new_drives:
            for d in new_drives:
                scan_paths.append(str(d))
                self.logger.info("new drive detected: %s", d)

        local_scan_paths = dlp_cfg.get("scan_paths") or []
        if local_scan_paths:
            scan_paths = list(local_scan_paths) + scan_paths

        if not scan_paths:
            scan_paths = default_paths
        elif not local_scan_paths:
            for p in default_paths:
                if p not in scan_paths:
                    scan_paths.append(p)

        monitored_extensions.update(e.lower() for e in (dlp_cfg.get("monitored_extensions") or []))
        monitored_extensions.update(DEFAULT_DLP_EXTENSIONS)
        paths = _expand_scan_paths(scan_paths)
        max_file_size = max_file_size_mb * 1024 * 1024

        if realtime_enabled and self._watcher is None:
            self.start_watcher(scan_paths, monitored_extensions)

        realtime_files = self.get_realtime_events()

        incidents = []
        known = set(self.state.get("incident_keys", []))
        alert_mtimes = self.state.get("alert_mtimes") or {}
        scan_cache = self.state.get("scan_cache") or {}
        updated_cache = {}
        started_at = time.monotonic()

        files_to_scan = []
        for path in _iter_files(paths, monitored_extensions, max_file_size, max_files_per_scan=max_files_per_scan):
            if max_scan_seconds > 0 and (time.monotonic() - started_at) >= max_scan_seconds:
                break
            files_to_scan.append(path)

        for rf in realtime_files:
            rp = Path(rf)
            if rp.exists() and rp.suffix.lower() in monitored_extensions:
                try:
                    if rp.stat().st_size <= max_file_size:
                        files_to_scan.append(rp)
                except Exception:
                    pass

        files_scanned = 0
        files_encrypted = 0
        files_quarantined = 0

        for path in files_to_scan:
            try:
                stat = path.stat()
                cache_value = f"{int(stat.st_mtime)}:{stat.st_size}"
            except Exception:
                continue
            cache_key = str(path).lower()
            updated_cache[cache_key] = cache_value
            if scan_cache.get(cache_key) == cache_value:
                continue
            files_scanned += 1

            is_encrypted, enc_type = _detect_encrypted(path)
            if is_encrypted:
                files_encrypted += 1

            content, file_meta = _read_file_content(path)
            haystack_all = _metadata_haystack(path, content, file_meta)
            haystack_content = content.lower() if content else ""
            haystack_meta = "\n".join(
                f"{k}:{v}" for k, v in {
                    "name": path.name, "path": str(path), "ext": path.suffix.lower(),
                    "owner": _file_owner(path),
                    **(file_meta or {}),
                }.items()
            ).lower()

            if not haystack_all.strip():
                continue

            for policy, rule in rules:
                pattern = (rule.get("pattern") or "").strip()
                if not pattern:
                    continue
                match_scope = (rule.get("match_scope") or "all").lower()
                if match_scope == "content":
                    haystack = haystack_content
                elif match_scope == "metadata":
                    haystack = haystack_meta
                elif match_scope == "filename":
                    haystack = path.name.lower()
                else:
                    haystack = haystack_all

                match_type = (rule.get("match_type") or "keyword").lower()
                matched_terms = []
                context_text = ""

                if match_type == "regex":
                    m = re.search(pattern, haystack, flags=re.IGNORECASE)
                    if m:
                        matched_terms.append(pattern)
                        context_text = _extract_context(haystack, m.start(), m.end())
                else:
                    pat_lower = pattern.lower()
                    idx = haystack.find(pat_lower)
                    if idx >= 0:
                        matched_terms.append(pattern)
                        context_text = _extract_context(haystack, idx, idx + len(pat_lower))

                if not matched_terms:
                    continue

                file_hash = _sha256(path)
                incident_key = hashlib.sha256(
                    f"{path}|{policy.get('code')}|{rule.get('name')}".encode("utf-8")
                ).hexdigest()
                prev_mtime = alert_mtimes.get(incident_key, 0)
                try:
                    cur_mtime = int(path.stat().st_mtime)
                except Exception:
                    cur_mtime = 0
                if incident_key in known and cur_mtime == prev_mtime:
                    continue
                known.add(incident_key)
                alert_mtimes[incident_key] = cur_mtime

                severity = rule.get("severity") or policy.get("severity", "high")
                quarantine = quarantine_enabled and severity in ("critical", "high")

                summary_parts = [f"Coincidencia DLP en {path.name}"]
                if context_text:
                    summary_parts.append(f"Contexto: {context_text[:300]}")
                if is_encrypted:
                    summary_parts.append(f"Archivo encriptado ({enc_type})")
                if file_meta:
                    interesting = {k: v for k, v in file_meta.items()
                                   if k in ("author", "creator", "title", "sheet_count", "page_count", "slide_count")}
                    if interesting:
                        summary_parts.append(f"Metadata: {json.dumps(interesting, ensure_ascii=False)}")

                incident = {
                    "fingerprint": incident_key,
                    "policy_code": policy.get("code", ""),
                    "rule_name": rule.get("name", ""),
                    "classification": rule.get("classification") or policy.get("code", ""),
                    "severity": severity,
                    "file_name": path.name,
                    "file_path": str(path),
                    "file_hash": file_hash,
                    "actor": _file_owner(path),
                    "channel": _path_channel(path),
                    "status": "open",
                    "detected_at": _utc_now(),
                    "summary": " | ".join(summary_parts),
                    "matched_keywords": matched_terms,
                    "context": context_text[:500] if context_text else "",
                    "encrypted": is_encrypted,
                    "encryption_type": enc_type,
                    "metadata": {
                        "size": path.stat().st_size if path.exists() else 0,
                        "suffix": path.suffix.lower(),
                        "created_at": datetime.fromtimestamp(
                            path.stat().st_ctime, tz=timezone.utc
                        ).isoformat() if path.exists() else "",
                        "modified_at": datetime.fromtimestamp(
                            path.stat().st_mtime, tz=timezone.utc
                        ).isoformat() if path.exists() else "",
                        **(file_meta or {}),
                    },
                }

                if quarantine and not is_encrypted:
                    if _quarantine_file(path, incident):
                        files_quarantined += 1
                        incident["quarantined"] = True

                incidents.append(incident)
                if len(incidents) >= 25:
                    self.queue_incidents(incidents)
                    incidents = []

        self.queue_incidents(incidents)
        self.state["incident_keys"] = sorted(list(known))[-5000:]
        self.state["alert_mtimes"] = dict(list(alert_mtimes.items())[-5000:])
        self.state["scan_cache"] = dict(list(updated_cache.items())[-25000:])
        self.state["last_scan_stats"] = {
            "files_scanned": files_scanned,
            "files_encrypted": files_encrypted,
            "files_quarantined": files_quarantined,
            "total_threats": len(incidents),
            "scanned_at": _utc_now(),
        }
        _save_state(self.state_path, self.state)

        if files_scanned > 0:
            self.logger.info(
                "scan complete: scanned=%d encrypted=%d quarantined=%d threats=%d",
                files_scanned, files_encrypted, files_quarantined, len(incidents),
            )

        return incidents

