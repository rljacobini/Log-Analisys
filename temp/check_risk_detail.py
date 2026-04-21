import sqlite3
from collections import Counter
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# All columns
c.execute("PRAGMA table_info(logs)")
print("Columns:")
for col in c.fetchall():
    print(f"  {col[1]}")

# Sample rows
c.execute("SELECT id, agent_id, source, attack_type, severity, risk FROM logs LIMIT 5")
print("\nSample rows:")
for row in c.fetchall():
    print(f"  id={row[0]}, agent={row[1]}, source={row[2]}, type={row[3]}, sev={row[4]}, risk={row[5]}")

# Risk distribution
c.execute("SELECT risk FROM logs")
risks = [r[0] for r in c.fetchall()]
print("\nRisk distribution:")
for k, v in sorted(Counter(risks).items()):
    print(f"  risk={k}: {v}")

# Count by ranges
print("\nBy ranges:")
print(f"  HIGH (30-49): {len([r for r in risks if 30 <= r < 50])}")
print(f"  CRITICAL (50-99): {len([r for r in risks if 50 <= r < 100])}")
print(f"  BREACH (100+): {len([r for r in risks if r >= 100])}")