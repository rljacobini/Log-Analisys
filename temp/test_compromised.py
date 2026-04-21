import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pcap.pcap_analyzer import PCAPAnalyzer

pcaps = [
    'pcaps/2024-08-15-traffic-analysis-exercise.pcap',
    'pcaps/2025-01-22-traffic-analysis-exercise.pcap',
    'pcaps/2025-06-13-traffic-analysis-exercise.pcap'
]

print('=== Compromised Hosts Analysis ===')
for p in pcaps:
    a = PCAPAnalyzer(p)
    r = a.analyze()
    f = r.get('forensic', {})
    s = f.get('summary', {})
    name = p.split('/')[1][:25]
    print(name + ':')
    print('  Compromised:', r.get('compromised_hosts'))
    print('  Critical:', s.get('critical', 0))
    print('  Lateral:', s.get('lateral_movements', 0))
    print('  External:', s.get('external_connections', 0))