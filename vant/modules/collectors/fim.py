from vant.modules.collectors.base import CollectorBase
import hashlib
import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any


class FIMCollector(CollectorBase):
    source_type = "fim"

    def __init__(self, cfg, agent_cfg):
        super().__init__(cfg, agent_cfg)
        self.state_dir = Path(__file__).resolve().parents[2] / ".vant_state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "fim_state.json"
        self.state = self._load_state()
        self.interval = float(agent_cfg.get("interval_seconds", 10))
        self.last_run = getattr(self, "_last_run", 0)

    def _load_state(self) -> Dict[str, Any]:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self):
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
        except Exception:
            pass

    def _hash_file(self, filepath: str) -> str:
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
        except Exception:
            return ""
        return hash_sha256.hexdigest()

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self.cfg or {}
        fim_cfg = cfg.get("fim", {})
        if not fim_cfg.get("enabled", True):
            return []

        paths = fim_cfg.get("paths", [])
        if isinstance(paths, str):
            paths = [paths]
        # Also allow scanning directories recursively
        recursive = fim_cfg.get("recursive", True)
        file_extensions = fim_cfg.get("extensions", None)  # list or None
        exclude_patterns = fim_cfg.get("exclude", [])  # list of substrings or regex? we'll do simple substring
        max_file_size = fim_cfg.get("max_file_size_mb", 10) * 1024 * 1024  # default 10 MB

        events = []
        now = time.time()
        # Optional: throttle to not run too often if interval small? We'll rely on agent interval.
        # We'll run every collection call.

        # Build list of files to check
        files_to_check = []
        for p in paths:
            p_obj = Path(p)
            if not p_obj.exists():
                continue
            if p_obj.is_file():
                files_to_check.append(p_obj)
            elif p_obj.is_dir():
                if recursive:
                    for root, dirs, files in os.walk(p_obj):
                        # Skip excluded directories? simple
                        for f in files:
                            fp = Path(root) / f
                            # Check extension filter
                            if file_extensions:
                                if fp.suffix.lower() not in [ext.lower() for ext in file_extensions]:
                                    continue
                            # Check exclude patterns
                            skip = False
                            for pat in exclude_patterns:
                                if pat in str(fp):
                                    skip = True
                                    break
                            if skip:
                                continue
                            # Check size
                            try:
                                if fp.stat().st_size > max_file_size:
                                    continue
                            except Exception:
                                continue
                            files_to_check.append(fp)
                else:
                    # only immediate files
                    for f in p_obj.iterdir():
                        if f.is_file():
                            files_to_check.append(f)

        for fp in files_to_check:
            try:
                stat = fp.stat()
                file_hash = self._hash_file(str(fp))
                if not file_hash:
                    continue
                prev = self.state.get(str(fp))
                if prev is None:
                    # New file
                    events.append({
                        "source_type": self.source_type,
                        "source_name": "fim",
                        "event_category": "fim.file.created",
                        "message": f"New file detected: {fp}",
                        "severity": "info",
                        "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "host_name": "",
                        "host_ip": "",
                        "raw_payload": {
                            "file_path": str(fp),
                            "file_size": stat.st_size,
                            "file_hash": file_hash,
                            "change_type": "created"
                        },
                        "tags": ["fim", "file_created"]
                    })
                else:
                    if prev.get("hash") != file_hash:
                        # Modified
                        events.append({
                            "source_type": self.source_type,
                            "source_name": "fim",
                            "event_category": "fim.file.modified",
                            "message": f"File modified: {fp}",
                            "severity": "low",
                            "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "host_name": "",
                            "host_ip": "",
                            "raw_payload": {
                                "file_path": str(fp),
                                "file_size": stat.st_size,
                                "file_hash": file_hash,
                                "previous_hash": prev.get("hash"),
                                "change_type": "modified"
                            },
                            "tags": ["fim", "file_modified"]
                        })
                    # size change could also be captured by hash change
                # Update state
                self.state[str(fp)] = {
                    "hash": file_hash,
                    "size": stat.st_size,
                    "last_checked": now
                }
            except Exception:
                # ignore errors on individual files
                continue

        # Detect deleted files (files in state that no longer exist)
        to_delete = []
        for file_path_str, info in list(self.state.items()):
            if not Path(file_path_str).exists():
                events.append({
                    "source_type": self.source_type,
                    "source_name": "fim",
                    "event_category": "fim.file.deleted",
                    "message": f"File deleted: {file_path_str}",
                    "severity": "info",
                    "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "host_name": "",
                    "host_ip": "",
                    "raw_payload": {
                        "file_path": file_path_str,
                        "previous_hash": info.get("hash"),
                        "change_type": "deleted"
                    },
                    "tags": ["fim", "file_deleted"]
                })
                to_delete.append(file_path_str)
        for fp in to_delete:
            del self.state[fp]

        if events:
            self._save_state()
        return events