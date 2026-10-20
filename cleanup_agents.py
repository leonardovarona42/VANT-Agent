import sys, os
os.environ['DJANGO_SETTINGS_MODULE'] = os.environ.get('DJANGO_SETTINGS_MODULE', 'CORE.settings')
base_dir = os.environ.get('VANT_SIEM_DIR', '/home/vant-siem')
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)
import django
django.setup()
from INVENTORY.models import Agent

agents = Agent.objects.all().order_by('last_heartbeat')
count = agents.count()
if count > 1:
    # Keep the newest one (has heartbeat and inventory)
    newest = agents.last()
    for a in agents:
        if a.agent_id != newest.agent_id:
            print(f"Deleting old agent: {a.agent_id} hostname={a.hostname} last_heartbeat={a.last_heartbeat}")
            a.delete()
    print(f"Kept agent: {newest.agent_id} hostname={newest.hostname}")
else:
    print(f"Only {count} agent(s), no cleanup needed")
