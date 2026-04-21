import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

# What agent shows (all pcap source)
c.execute("SELECT attack_type, COUNT(*) FROM logs WHERE source='pcap_analysis_pcap' GROUP BY attack_type")
print('Agent shows (source=pcap_analysis_pcap):')
for r in c.fetchall():
    print(f'  {r[0]}: {r[1]}')
total_agent = sum(r[1] for r in c.fetchall())
print(f'  TOTAL: {total_agent}')

# What PCAP page shows (filtered)
c.execute("SELECT attack_type, COUNT(*) FROM logs WHERE (attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%') GROUP BY attack_type")
print('\nPCAP page shows (filtered):')
for r in c.fetchall():
    print(f'  {r[0]}: {r[1]}')
total_pcap = sum(r[1] for r in c.fetchall())
print(f'  TOTAL: {total_pcap}')

# What's missing from PCAP
missing = total_agent - total_pcap
print(f'\nMissing from PCAP filter: {missing}')
print('These are network_enumeration and weak_crypto')