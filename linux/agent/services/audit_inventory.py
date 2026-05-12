import hashlib
import json
import os
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _safe_json_command(command):
    try:
        out = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
        out = out.strip()
        if not out:
            return []
        data = json.loads(out)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except Exception:
        return []


def _safe_text_command(command):
    try:
        return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def _state_dir(config_path):
    base = Path(config_path).resolve().parent
    state_dir = base / ".agent_state"
    state_dir.mkdir(parents=True, exist_ok=True)
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


def _normalize_apps(items):
    apps = []
    for item in items:
        name = item.get("DisplayName") or item.get("Name") or item.get("name") or ""
        if not name:
            continue
        version = item.get("DisplayVersion") or item.get("Version") or item.get("version") or ""
        publisher = item.get("Publisher") or item.get("Vendor") or item.get("publisher") or ""
        apps.append(
            {
                "name": name,
                "version": version,
                "publisher": publisher,
                "fingerprint": f"{name}|{version}|{publisher}".lower()[:255],
            }
        )
    return apps


def _collect_linux_inventory():
    hostname = socket.gethostname()
    inventory = {
        "host": hostname,
        "os": platform.platform(),
        "collected_at": _utc_now(),
        "hardware": [],
        "software": [],
        "network": [],
        "users": [],
        "usb_devices": [],
        "raw": {},
    }

    cpuinfo = _safe_text_command("cat /proc/cpuinfo")
    meminfo = _safe_text_command("cat /proc/meminfo")
    inventory["raw"]["cpuinfo"] = cpuinfo
    inventory["raw"]["meminfo"] = meminfo

    cpu_model = ""
    cpu_cores = 0
    for line in cpuinfo.splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[-1].strip()
        if line.startswith("processor"):
            cpu_cores += 1
    if cpu_model:
        inventory["hardware"].append({
            "component_type": "cpu", "name": cpu_model, "vendor": "",
            "model": "", "serial_number": "",
            "fingerprint": f"cpu|{cpu_model}",
        })

    total_mem_kb = 0
    for line in meminfo.splitlines():
        if line.startswith("MemTotal"):
            total_mem_kb = int(line.split()[1])
            break
    inventory["raw"]["memory_kb"] = total_mem_kb
    inventory["hardware"].append({
        "component_type": "memory", "name": f"{total_mem_kb // 1024} MB",
        "vendor": "", "model": "", "serial_number": "",
        "fingerprint": f"mem|{total_mem_kb}",
        "metadata": {"size_kb": total_mem_kb},
    })

    dmi = _safe_text_command("cat /sys/class/dmi/id/product_name 2>/dev/null")
    dmi_vendor = _safe_text_command("cat /sys/class/dmi/id/sys_vendor 2>/dev/null")
    dmi_serial = _safe_text_command("cat /sys/class/dmi/id/product_serial 2>/dev/null")
    bios_version = _safe_text_command("cat /sys/class/dmi/id/bios_version 2>/dev/null")
    inventory["raw"]["dmi_product"] = dmi
    inventory["raw"]["dmi_vendor"] = dmi_vendor
    inventory["raw"]["dmi_serial"] = dmi_serial
    inventory["raw"]["bios_version"] = bios_version

    inventory["hardware"].append({
        "component_type": "system", "name": dmi or "System",
        "vendor": dmi_vendor, "model": dmi, "serial_number": dmi_serial,
        "fingerprint": f"system|{dmi_serial}|{dmi}",
    })
    inventory["hardware"].append({
        "component_type": "bios", "name": "BIOS",
        "vendor": "", "model": bios_version, "serial_number": "",
        "fingerprint": f"bios|{bios_version}",
    })

    lsblk_out = _safe_text_command("lsblk -d -o NAME,SIZE,MODEL,ROTA,TRAN 2>/dev/null")
    inventory["raw"]["lsblk"] = lsblk_out
    for line in lsblk_out.splitlines():
        parts = line.split()
        if not parts or parts[0] == "NAME":
            continue
        dev_name = parts[0]
        size = parts[1] if len(parts) > 1 else ""
        model = " ".join(parts[2:-2]) if len(parts) > 4 else ""
        fingerprint = f"disk|{dev_name}"
        if not any(d.get("fingerprint") == fingerprint for d in inventory["hardware"]):
            inventory["hardware"].append({
                "component_type": "disk", "name": dev_name,
                "vendor": "", "model": model, "serial_number": "",
                "fingerprint": fingerprint,
                "metadata": {"size": size, "device": dev_name},
            })

    net_out = _safe_text_command("ip -o addr show 2>/dev/null")
    inventory["raw"]["ip_addr"] = net_out
    for line in net_out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            iface = parts[1].strip(":")
            ip_addr = parts[3] if parts[2] == "inet" else None
            if ip_addr and iface != "lo":
                inventory["network"].append({
                    "address_type": "ipv4", "address": ip_addr.split("/")[0],
                    "interface_name": iface,
                    "fingerprint": f"ipv4|{iface}|{ip_addr.split('/')[0]}",
                })

    mac_out = _safe_text_command("ip link show 2>/dev/null")
    mac_seen = set()
    for line in mac_out.splitlines():
        if "link/ether" in line:
            parts = line.split()
            mac = parts[1]
            iface = line.split(":")[1].strip() if ":" in line else ""
            if mac and mac not in mac_seen and iface != "lo":
                mac_seen.add(mac)
                inventory["network"].append({
                    "address_type": "mac", "address": mac,
                    "mac_address": mac, "interface_name": iface,
                    "fingerprint": f"mac|{iface}|{mac}",
                })
                inventory["hardware"].append({
                    "component_type": "network", "name": iface,
                    "vendor": "", "model": "", "serial_number": mac,
                    "fingerprint": f"nic|{iface}|{mac}",
                    "metadata": {"mac": mac, "interface": iface},
                })

    dpkg_out = _safe_text_command("dpkg-query -f '${Package}|${Version}|${Maintainer}|${Status}\\n' -W 2>/dev/null | grep ' installed$' | head -2000")
    inventory["raw"]["packages"] = dpkg_out
    for line in dpkg_out.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 3:
            inventory["software"].append({
                "name": parts[0], "version": parts[1],
                "publisher": parts[2].split("<")[0].strip() if "<" in parts[2] else parts[2],
                "fingerprint": f"{parts[0]}|{parts[1]}".lower()[:255],
            })

    who_out = _safe_text_command("who -u 2>/dev/null")
    inventory["raw"]["who"] = who_out
    for line in who_out.splitlines():
        parts = line.split()
        if len(parts) >= 1:
            username = parts[0]
            fingerprint = username.lower()
            if not any(u.get("username", "").lower() == fingerprint for u in inventory["users"]):
                inventory["users"].append({
                    "username": username, "session_name": parts[1] if len(parts) > 1 else "",
                    "session_id": parts[2] if len(parts) > 2 else "",
                    "state": parts[4] if len(parts) > 4 else "active",
                    "idle_time": parts[5] if len(parts) > 5 else "",
                    "logon_time": " ".join(parts[6:]) if len(parts) > 6 else "",
                    "raw": line.strip(),
                })

    usb_out = _safe_text_command("lsusb 2>/dev/null")
    inventory["raw"]["lsusb"] = usb_out
    for line in usb_out.splitlines():
        parts = line.split(None, 6)
        if len(parts) >= 6:
            name = parts[-1] if len(parts) > 6 else "USB Device"
            dev_id = parts[5] if len(parts) > 5 else ""
            fingerprint = f"usb|{dev_id}"
            if not any(d.get("fingerprint") == fingerprint for d in inventory["usb_devices"]):
                inventory["usb_devices"].append({
                    "name": name, "device_id": dev_id,
                    "status": "present", "vendor": parts[6] if len(parts) > 6 else "",
                    "fingerprint": fingerprint,
                })
                inventory["hardware"].append({
                    "component_type": "usb", "name": name,
                    "vendor": parts[6] if len(parts) > 6 else "",
                    "model": "", "serial_number": dev_id,
                    "fingerprint": f"usb|{dev_id}",
                })

    return inventory


class AuditInventoryService:
    service_name = "asset_audit"

    def __init__(self, config_path):
        self.config_path = config_path
        self.state_path = _state_dir(config_path) / "audit_inventory_state.json"
        self.state = _load_state(self.state_path)

    def collect(self):
        inventory = _collect_linux_inventory()

        events = self._build_timeline_events(inventory)
        inventory["timeline_events"] = events
        self.state = {
            "software": sorted([item["fingerprint"] for item in inventory.get("software", [])]),
            "network": sorted([item["fingerprint"] for item in inventory.get("network", []) if item.get("fingerprint")]),
            "usb": sorted([item["fingerprint"] for item in inventory.get("usb_devices", []) if item.get("fingerprint")]),
            "users": sorted([item["username"] for item in inventory.get("users", []) if item.get("username")]),
        }
        _save_state(self.state_path, self.state)
        return inventory

    def _build_timeline_events(self, inventory):
        now = _utc_now()
        previous = self.state or {}
        events = []

        previous_software = set(previous.get("software", []))
        current_software = {item["fingerprint"]: item for item in inventory.get("software", []) if item.get("fingerprint")}
        for fingerprint, item in current_software.items():
            if fingerprint not in previous_software:
                events.append(
                    {
                        "category": "software",
                        "event_type": "software_observed",
                        "title": f"Software detectado: {item.get('name', '')}",
                        "description": f"Version {item.get('version', '')} publisher {item.get('publisher', '')}",
                        "severity": "info",
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        previous_network = set(previous.get("network", []))
        current_network = {item["fingerprint"]: item for item in inventory.get("network", []) if item.get("fingerprint")}
        for fingerprint, item in current_network.items():
            if fingerprint not in previous_network:
                events.append(
                    {
                        "category": "network",
                        "event_type": "network_identity_observed",
                        "title": f"Red detectada: {item.get('address', '')}",
                        "description": item.get("interface_name", ""),
                        "severity": "info",
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        previous_usb = set(previous.get("usb", []))
        current_usb = {item["fingerprint"]: item for item in inventory.get("usb_devices", []) if item.get("fingerprint")}
        for fingerprint, item in current_usb.items():
            if fingerprint not in previous_usb:
                events.append(
                    {
                        "category": "usb",
                        "event_type": "usb_device_observed",
                        "title": f"USB detectado: {item.get('name', '')}",
                        "description": item.get("device_id", ""),
                        "severity": "medium",
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        previous_users = set(previous.get("users", []))
        current_users = {item["username"]: item for item in inventory.get("users", []) if item.get("username")}
        for username, item in current_users.items():
            if username not in previous_users:
                events.append(
                    {
                        "category": "user",
                        "event_type": "user_session_observed",
                        "title": f"Usuario detectado: {username}",
                        "description": item.get("raw", ""),
                        "severity": "info",
                        "actor": username,
                        "observed_at": now,
                        "source_service": self.service_name,
                        "metadata": item,
                    }
                )

        return events
