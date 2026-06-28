#!/usr/bin/env python3
import sys
sys.path.insert(0, '/tmp/vant-build/linux/agent')
sys.path.insert(0, '/tmp/vant-build/linux/agent/services')
from services.audit_inventory import _collect_linux_inventory

inv = _collect_linux_inventory()
print('Hardware:', len(inv.get('hardware', [])))
for h in inv.get('hardware', []):
    print(' ', h['component_type'], ':', h.get('name', ''))
print('Software:', len(inv.get('software', [])))
for sw in inv.get('software', [])[:3]:
    print(' ', sw.get('name'), sw.get('version'))
print('Network:', len(inv.get('network', [])))
print('Users:', len(inv.get('users', [])))
print('USB:', len(inv.get('usb_devices', [])))
