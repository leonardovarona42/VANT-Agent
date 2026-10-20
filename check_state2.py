import sys, os
os.environ['DJANGO_SETTINGS_MODULE'] = os.environ.get('DJANGO_SETTINGS_MODULE', 'CORE.settings')
base_dir = os.environ.get('VANT_SIEM_DIR', '/home/vant-siem')
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)
import django
django.setup()
from INVENTORY.models import Agent, HardwareInventory, SoftwareInventory

# Keep only newest agent
agents = Agent.objects.all().order_by('last_heartbeat')
if agents.count() > 1:
    newest = agents.last()
    for a in agents:
        if a.agent_id != newest.agent_id:
            print(f"Deleting old: {a.agent_id} {a.hostname}")
            a.delete()
    print(f"Kept: {newest.agent_id} {newest.hostname}")

# Check HW details
print("\n--- Hardware ---")
for h in HardwareInventory.objects.all():
    print(f"  cpu={h.cpu_model} ram={h.ram_total_gb}GB")
    print(f"  disks={len(h.disks)} net_ifaces={len(h.network_interfaces)}")

print(f"\nSoftware: {SoftwareInventory.objects.count()} packages")
if SoftwareInventory.objects.exists():
    sw = SoftwareInventory.objects.first()
    print(f"  First: {sw.name} {sw.version} {sw.publisher}")
