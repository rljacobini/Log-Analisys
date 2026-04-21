import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()
c.execute("SELECT risk, severity FROM logs WHERE attack_type LIKE '%download%' LIMIT 5")
print("Risk vs Severity:")
for row in c.fetchall():
    print(f"  risk={row[0]}, severity={row[1]}")