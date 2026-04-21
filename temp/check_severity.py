import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# All severity counts
c.execute("SELECT severity, COUNT(*) FROM logs GROUP BY severity")
print("All severities:")
for row in c.fetchall():
    print(f"  {row[0]}: {row[1]}")

# Filtered severity counts  
c.execute("SELECT severity, COUNT(*) FROM logs WHERE attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%' GROUP BY severity")
print("\nFiltered severities:")
for row in c.fetchall():
    print(f"  {row[0]}: {row[1]}")