#!/usr/bin/env python3
import sys
sys.path.insert(0, '/tmp/vant-build/linux/agent')
sys.path.insert(0, '/tmp/vant-build/linux/agent/services')
from services.audit_inventory import _collect_linux_inventory

# Import _build_inventory_payload from agent.py
import importlib.util
spec = importlib.util.spec_from_file_location("agent", "/tmp/vant-build/linux/agent/agent.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

inv = _collect_linux_inventory()
payload = mod._build_inventory_payload("test-agent", inv)

print('Payload agent_id:', payload.get('agent_id'))
print('Payload hardware keys:', list(payload.get('hardware', {}).keys()))
print('Payload software count:', len(payload.get('software', [])))
print()
print('Full hardware payload:')
for k, v in payload.get('hardware', {}).items():
    if isinstance(v, list):
        print(f'  {k}: {len(v)} items')
        if v:
            print(f'    first: {v[0]}')
    else:
        print(f'  {k}: {v}')
