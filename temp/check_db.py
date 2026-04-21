import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# Total logs
c.execute("SELECT COUNT(*) FROM logs")
print(f"Total logs: {c.fetchone()[0]}")

# By source
c.execute("SELECT source, COUNT(*) FROM logs GROUP BY source")
print("\nBy source:")
for row in c.fetchall():
    print(f"  {row[0]}: {row[1]}")

# By attack_type
c.execute("SELECT attack_type, COUNT(*) FROM logs GROUP BY attack_type")
print("\nBy attack_type:")
for row in c.fetchall():
    print(f"  {row[0]}: {row[1]}")

# By severity
c.execute("SELECT severity, COUNT(*) FROM logs GROUP BY severity")
print("\nBy severity:")
for row in c.fetchall():
    print(f"  {row[0]}: {row[1]}")

# Risk distribution
c.execute("SELECT risk, COUNT(*) FROM logs GROUP BY risk ORDER BY risk")
print("\nBy risk:")
for row in c.fetchall():
    print(f"  risk={row[0]}: {row[1]}")