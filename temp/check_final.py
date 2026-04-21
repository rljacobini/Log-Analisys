import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# What agent shows (all pcap source)
c.execute("SELECT COUNT(*) FROM logs WHERE source='pcap_analysis_pcap'")
total_agent = c.fetchone()[0]
print(f'Agent shows: {total_agent}')

# What PCAP page shows (filtered)
c.execute("SELECT COUNT(*) FROM logs WHERE attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%'")
total_pcap = c.fetchone()[0]
print(f'PCAP page: {total_pcap}')

c.execute('SELECT COUNT(*) FROM logs')
total = c.fetchone()[0]
print(f'Dashboard Total: {total}')

print(f'\n--- BREAKDOWN ---')
print(f'172 total - 165 filtered = 7 not shown in PCAP')
print(f'170 pcap source - 165 filtered = 5 not filtered but only showing 165?')

# Exact breakdown
c.execute("SELECT source, attack_type, COUNT(*) FROM logs GROUP BY source, attack_type")
print('\nAll sources x attack_type:')
for r in c.fetchall():
    print(f'  {r[0]} x {r[1]}: {r[2]}')