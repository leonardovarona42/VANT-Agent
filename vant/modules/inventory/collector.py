import json
import platform
import socket
import subprocess


def safe_json_command(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
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
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def detect_os_type():
    system = platform.system().lower()
    if system != "windows":
        return "other"
    release = platform.release()
    version = platform.version()
    if "10.0." in version:
        build = version.split(".")[-1]
        try:
            if int(build) >= 22000:
                return "windows_11"
        except Exception:
            pass
        return "windows_10"
    if "2022" in platform.win32_ver()[2]:
        return "windows_server_2022"
    if "2019" in platform.win32_ver()[2]:
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


def collect_windows_software():
    apps = safe_json_command(
        'powershell -NoProfile -Command "Get-ItemProperty '
        'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | '
        'Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,EstimatedSize | '
        'ConvertTo-Json -Compress"'
    )
    sw_list = []
    for item in apps:
        name = item.get("DisplayName", "")
        if not name:
            continue
        size_mb = 0
        est = item.get("EstimatedSize")
        if est:
            try:
                size_mb = round(int(est) / 1024, 1)
            except Exception:
                pass
        sw_list.append({
            "name": name,
            "version": item.get("DisplayVersion", ""),
            "publisher": item.get("Publisher", ""),
            "install_date": item.get("InstallDate", ""),
            "size_mb": size_mb,
            "is_system": False,
        })
    return sw_list
