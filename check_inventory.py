import sys, os
os.environ['DJANGO_SETTINGS_MODULE'] = os.environ.get('DJANGO_SETTINGS_MODULE', 'CORE.settings')
base_dir = os.environ.get('VANT_SIEM_DIR', '/home/vant-siem')
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)
import django
django.setup()
from INVENTORY.models import Agent, HardwareInventory, SoftwareInventory

agents = Agent.objects.all()
print(f"Agents: {agents.count()}")
for a in agents:
    meta = a.meta or {}
    print(f"  {a.agent_id} hostname={a.hostname} status={a.status}")
    print(f"  last_heartbeat={a.last_heartbeat} last_inventory={a.last_inventory_at}")
    
hw = HardwareInventory.objects.all()
print(f"\nHardware inventories: {hw.count()}")
for h in hw:
    print(f"  Agent={h.agent_id} cpu={h.cpu_model} ram={h.ram_total_gb}GB")
    
sw = SoftwareInventory.objects.all()
print(f"\nSoftware inventories: {sw.count()}")
names = set(s.name for s in sw)
print(f"  Unique software: {len(names)}")
print(f"  First 5: {sorted(names)[:5]}")
