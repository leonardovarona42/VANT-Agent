from INVENTORY.models import Agent
agents = Agent.objects.all()
print(f"Agents: {agents.count()}")
for a in agents:
    meta = a.meta or {}
    print(f"  {a.agent_id} {a.hostname} {a.status} original_id={meta.get('original_agent_id', '')}")
