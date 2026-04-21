import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# Check NULL in risk column
c.execute("SELECT risk FROM logs")
risks = [r[0] for r in c.fetchall()]
print(f"Total rows: {len(risks)}")

# Count None/null
null_count = len([r for r in risks if r is None])
print(f"NULL risk: {null_count}")

# If we filter out None
valid_risks = [r for r in risks if r is not None]
print(f"Valid risks: {len(valid_risks)}")
print(f"With None in list comprehension:")

# This is what dashboard does
test_high = len([r for r in risks if 30 <= r < 50])  # This would cause error with None!
print(f"  HIGH: {test_high}")