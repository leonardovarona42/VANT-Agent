import json
import logging
import os
import platform
import re
import socket
import subprocess

from vant.utils import run_hidden


def safe_json_command(cmd):
    try:
        proc = run_hidden(cmd, capture_output=True, text=True, timeout=30, check=False)
        out = proc.stdout.strip()
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


def safe_text_command(cmd):
    try:
        proc = run_hidden(cmd, capture_output=True, text=True, timeout=15, check=False)
        return proc.stdout.strip()
    except Exception:
        return ""


def detect_os_type():
    system = platform.system().lower()
    if system != "windows":
        return "other"
    version = platform.version()
    release = platform.release()
    if "10.0." in version:
        build = version.split(".")[-1]
        try:
            if int(build) >= 22000:
                return "windows_11"
        except Exception:
            pass
    if "11" in release:
        return "windows_11"
    ver_info = platform.win32_ver()[2]
    if "Server" in ver_info or "server" in ver_info.lower():
        if "2025" in ver_info:
            return "windows_server_2025"
        if "2022" in ver_info:
            return "windows_server_2022"
        if "2019" in ver_info:
            return "windows_server_2019"
    return "windows_10"


def collect_windows_hardware():
    hw = {}
    systems = safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_ComputerSystem | '
        'Select-Object Manufacturer,Model,TotalPhysicalMemory,Name,Domain | '
        'ConvertTo-Json -Compress"'
    )
    for item in systems:
        hw["manufacturer"] = item.get("Manufacturer", "")
        hw["product_name"] = item.get("Model", "")
        ram_bytes = item.get("TotalPhysicalMemory", 0)
        hw["ram_total_gb"] = round(ram_bytes / (1024**3), 1) if ram_bytes else 0
        hw["host_name"] = item.get("Name", socket.gethostname())
        hw["domain"] = item.get("Domain", "")

    cpus = safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_Processor | '
        'Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | '
        'ConvertTo-Json -Compress"'
    )
    cpu_list = []
    for item in cpus:
        cpu_list.append({
            "model": item.get("Name", ""),
            "cores": item.get("NumberOfCores", 0),
            "threads": item.get("NumberOfLogicalProcessors", 0),
            "speed_ghz": round(item.get("MaxClockSpeed", 0) / 1000, 2),
        })
    if cpu_list:
        c = cpu_list[0]
        hw["cpu_model"] = c["model"]
        hw["cpu_cores"] = c["cores"]
        hw["cpu_threads"] = c["threads"]
        hw["cpu_speed_ghz"] = c["speed_ghz"]

    bios = safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_BIOS | '
        'Select-Object SerialNumber,Manufacturer,SMBIOSBIOSVersion | '
        'ConvertTo-Json -Compress"'
    )
    for item in bios:
        hw["serial_number"] = item.get("SerialNumber", "")
        hw["bios_version"] = item.get("SMBIOSBIOSVersion", "")

    boards = safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_BaseBoard | '
        'Select-Object Product,Manufacturer | ConvertTo-Json -Compress"'
    )
    for item in boards:
        if not hw.get("motherboard_model"):
            hw["motherboard_model"] = item.get("Product", "")
            hw["motherboard_manufacturer"] = item.get("Manufacturer", "")

    disks = safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_DiskDrive | '
        'Select-Object Model,Manufacturer,SerialNumber,Size,InterfaceType,MediaType | '
        'ConvertTo-Json -Compress"'
    )
    disk_list = []
    for item in disks:
        size_gb = 0
        if item.get("Size"):
            size_gb = round(int(item["Size"]) / (1000**3), 1)
        disk_list.append({
            "name": item.get("Model", "Disk"),
            "size_gb": size_gb,
            "type": item.get("MediaType", item.get("InterfaceType", "")),
            "serial": item.get("SerialNumber", ""),
        })
    hw["disks"] = disk_list

    gpus = safe_json_command(
        'powershell -NoProfile -Command "Get-CimInstance Win32_VideoController | '
        'Select-Object Name | ConvertTo-Json -Compress"'
    )
    hw["gpu_models"] = [g.get("Name", "") for g in gpus if g.get("Name")]

    adapters = safe_json_command(
        'powershell -NoProfile -Command "Get-NetAdapter | '
        'Select-Object Name,InterfaceDescription,MacAddress,Status,LinkSpeed | '
        'ConvertTo-Json -Compress"'
    )
    ifaces = []
    for a in adapters:
        ifaces.append({
            "name": a.get("Name", ""),
            "mac": a.get("MacAddress", ""),
            "status": a.get("Status", ""),
            "speed": a.get("LinkSpeed", ""),
        })
    hw["network_interfaces"] = ifaces

    return hw


def _parse_install_date(raw):
    if not raw:
        return None
    raw = str(raw).strip()
    if len(raw) == 8 and raw.isdigit():
        return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]}"
    return raw


def collect_windows_software():
    ps_cmd = 'powershell -NoProfile -Command "$r=@(); ' \
        "foreach ($k in @(" \
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', " \
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')) {" \
        "  Get-ItemProperty $k -ErrorAction SilentlyContinue | ?{$_.DisplayName} | %{" \
        "    $r+=@{n=$_.DisplayName;v=$_.DisplayVersion;p=$_.Publisher;d=$_.InstallDate;s=$_.EstimatedSize}" \
        "  }" \
        "}; " \
        '$r|ConvertTo-Json -Compress"'
    apps = safe_json_command(ps_cmd)
    sw_list = []
    seen = set()
    for item in apps:
        name = item.get("n", "")
        if not name:
            continue
        version = item.get("v", "")
        publisher = item.get("p", "")
        key = (name, version, publisher)
        if key in seen:
            continue
        seen.add(key)
        size_mb = 0
        est = item.get("s")
        if est:
            try:
                size_mb = round(int(est) / 1024, 1)
            except Exception:
                pass
        sw_list.append({
            "name": name,
            "version": version or "",
            "publisher": publisher or "",
            "install_date": _parse_install_date(item.get("d", "")),
            "size_mb": size_mb,
            "is_system": False,
        })
    return sw_list


def collect_linux_hardware():
    hw = {}
    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()
        for line in cpuinfo.splitlines():
            if line.startswith("model name"):
                hw["cpu_model"] = line.split(":", 1)[-1].strip()
                break
    except Exception:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    hw["ram_total_gb"] = round(kb / (1024 * 1024), 1)
                    break
    except Exception:
        pass
    try:
        paths = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_serial",
            "/sys/class/dmi/id/bios_version",
        ]
        for p in paths:
            try:
                with open(p) as f:
                    val = f.read().strip()
                    if "product_name" in p:
                        hw["product_name"] = val
                    elif "sys_vendor" in p:
                        hw["manufacturer"] = val
                    elif "product_serial" in p:
                        hw["serial_number"] = val
                    elif "bios_version" in p:
                        hw["bios_version"] = val
            except Exception:
                pass
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["lsblk", "-d", "-o", "NAME,SIZE,MODEL", "--json"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            disks = []
            for dev in data.get("blockdevices", []):
                disks.append({
                    "name": dev.get("model", dev.get("name", "")),
                    "size_gb": dev.get("size", ""),
                    "type": "disk",
                    "serial": "",
                })
            hw["disks"] = disks
    except Exception:
        pass
    hw["gpu_models"] = []
    hw["network_interfaces"] = []
    hw["cpu_cores"] = os.cpu_count() or 0
    return hw


def collect_linux_software():
    sw_list = []
    try:
        result = subprocess.run(
            ["dpkg-query", "-f", "${Package}|${Version}|${Maintainer}\n", "-W"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.strip().split("|")
                if len(parts) >= 2:
                    name, version = parts[0], parts[1]
                    publisher = parts[2].split("<")[0].strip() if len(parts) > 2 and "<" in parts[2] else (parts[2] if len(parts) > 2 else "")
                    sw_list.append({
                        "name": name,
                        "version": version,
                        "publisher": publisher,
                        "install_date": None,
                        "size_mb": 0,
                        "is_system": True,
                    })
    except Exception:
        pass
    if not sw_list:
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{VENDOR}\n"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.strip().split("|")
                    if len(parts) >= 2:
                        sw_list.append({
                            "name": parts[0],
                            "version": parts[1],
                            "publisher": parts[2] if len(parts) > 2 else "",
                            "install_date": None,
                            "size_mb": 0,
                            "is_system": True,
                        })
        except Exception:
            pass
    return sw_list
