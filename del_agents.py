import sys, os
os.environ['DJANGO_SETTINGS_MODULE'] = os.environ.get('DJANGO_SETTINGS_MODULE', 'CORE.settings')
base_dir = os.environ.get('VANT_SIEM_DIR', '/home/vant-siem')
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)
import django
django.setup()
from INVENTORY.models import Agent
Agent.objects.all().delete()
print("Done - all agents deleted")
