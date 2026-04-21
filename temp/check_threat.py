import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# Check threat_intel table
c.execute("SELECT * FROM threat_intel")
print("Threat intel:")
for row in c.fetchall():
    print(f"  {row}")

print("\n---")

# Check alerts in more detail
c.execute("SELECT src_ip, risk, attack_type, agent_id FROM alerts")
print("\nAlerts:")
for row in c.fetchall():
    print(f"  {row}")