import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# Check agents table
c.execute("SELECT * FROM agents")
agents = c.fetchall()
print(f"Agents: {len(agents)}")
for a in agents[:5]:
    print(f"  {a}")

# Check alerts table
c.execute("SELECT COUNT(*) FROM alerts")
print(f"\nAlerts: {c.fetchone()[0]}")

# Check threat_intel table
c.execute("SELECT COUNT(*) FROM threat_intel")
print(f"Threat intel: {c.fetchone()[0]}")

# Check for any alerts related to this agent
c.execute("SELECT * FROM alerts WHERE agent_id='pcap-analyzer-01' LIMIT 3")
alerts = c.fetchall()
print(f"\nAlerts for pcap-analyzer-01: {len(alerts)}")
for a in alerts[:3]:
    print(f"  {a}")