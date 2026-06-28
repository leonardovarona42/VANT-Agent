#!/usr/bin/env python3
import sys
sys.path.insert(0, '/tmp/vant-build/linux/agent')
sys.path.insert(0, '/tmp/vant-build/linux/agent/services')
from services.audit_inventory import _collect_linux_inventory

# Replicate _build_inventory_payload logic
def build_payload(agent_id, inventory):
    hw_list = inventory.get("hardware", []) or []
    hw = {}
    for item in hw_list:
        ct = item.get("component_type", "")
        if ct == "cpu":
            hw["cpu_model"] = item.get("name", "")
        elif ct == "board":
            hw["motherboard_model"] = item.get("model", "")
            hw["motherboard_manufacturer"] = item.get("vendor", "")
        elif ct == "bios":
            hw["bios_version"] = item.get("model", "")
            hw["serial_number"] = item.get("serial_number", "")
        elif ct == "system":
            hw["manufacturer"] = item.get("vendor", "")
            hw["product_name"] = item.get("name", "")
        elif ct == "disk":
            hw.setdefault("disks", []).append(item)
        elif ct == "network":
            hw.setdefault("network_interfaces", []).append(item)
    return {
        "agent_id": agent_id,
        "hardware": hw,
        "software": inventory.get("software", []) or [],
    }

inv = _collect_linux_inventory()
payload = build_payload("test-agent", inv)

print('Payload agent_id:', payload.get('agent_id'))
print('Payload hardware keys:', list(payload.get('hardware', {}).keys()))
print('Payload software count:', len(payload.get('software', [])))
for k, v in payload.get('hardware', {}).items():
    if isinstance(v, list):
        print(f'  {k}: {len(v)} items')
        if v:
            print(f'    first: {dict(list(v[0].items())[:3])}')
    else:
        print(f'  {k}: {v}')
