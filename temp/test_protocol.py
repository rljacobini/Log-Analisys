import sqlite3

conn = sqlite3.connect('server/database.db')
c = conn.cursor()
c.execute('SELECT id, src_ip, attack_type, protocol, src_port FROM logs WHERE agent_id = "test"')
print(c.fetchall())
conn.close()