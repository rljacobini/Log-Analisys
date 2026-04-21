import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

c.execute("SELECT attack_type, COUNT(*) FROM logs WHERE source='pcap_analysis_pcap' GROUP BY attack_type")
print('PCAP attack types:')
for r in c.fetchall():
    print(f'  {r[0]}: {r[1]}')

c.execute("SELECT COUNT(*) FROM logs WHERE attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%'")
filtered = c.fetchone()[0]
print(f'\nFiltered count: {filtered}')

c.execute("SELECT COUNT(*) FROM logs WHERE source='pcap_analysis_pcap' AND (attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%')")
pcap_filtered = c.fetchone()[0]
print(f'PCAP filtered: {pcap_filtered}')