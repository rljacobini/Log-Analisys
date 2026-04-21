import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

c.execute("SELECT risk FROM logs")
risks = [r[0] for r in c.fetchall()]

print(f"Total: {len(risks)}")
print(f"All risks: {sorted(set(risks))}")
print(f"\nDashboard logic:")
print(f"  Bajo (0-14): {len([r for r in risks if r < 15])}")
print(f"  Medio (15-29): {len([r for r in risks if 15 <= r < 30])}")
print(f"  Alto (30-49): {len([r for r in risks if 30 <= r < 50])}")
print(f"  Critico (50-99): {len([r for r in risks if 50 <= r < 100])}")
print(f"  Breach (100+): {len([r for r in risks if r >= 100])}")

print(f"\nstats.high (30-49): {len([r for r in risks if 30 <= r < 50])}")
print(f"stats.critical (50-99): {len([r for r in risks if 50 <= r < 100])}")
print(f"stats.breach (100+): {len([r for r in risks if r >= 100])}")