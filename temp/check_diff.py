import sqlite3
conn = sqlite3.connect('server/database.db')
c = conn.cursor()

c.execute("SELECT COUNT(*) FROM logs WHERE attack_type LIKE '%download%' OR attack_type LIKE '%flood%' OR attack_type LIKE '%c2%' OR attack_type LIKE '%scan%' OR attack_type LIKE '%malware%'")
total_pcap = c.fetchone()[0]
print(f'PCAP filtered (all sources): {total_pcap}')

c.execute("SELECT COUNT(*) FROM logs WHERE source='pcap_analysis_pcap'")
agent_count = c.fetchone()[0]
print(f'Agent (pcap source only): {agent_count}')

c.execute('SELECT COUNT(*) FROM logs')
total = c.fetchone()[0]
print(f'Total: {total}')

# Difference
print(f'\nDifference: {agent_count - total_pcap}')
print(f'Difference: {total - agent_count}')

# Which attack types are NOT in PCAP filter
c.execute("SELECT attack_type, COUNT(*) FROM logs WHERE source='pcap_analysis_pcap'")
print('\nPCAP source attack types:')
for r in c.fetchall():
    print(f'  {r[0]}: {r[1]}')