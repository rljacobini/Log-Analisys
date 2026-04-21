import requests
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcap.pcap_analyzer import PCAPAnalyzer

pcaps = [
    'pcaps/2020-12-31-traffic-analysis-quiz-01.pcap',
    'pcaps/2020-12-31-traffic-analysis-quiz-02.pcap',
    'pcaps/2020-12-31-traffic-analysis-quiz-03.pcap',
    'pcaps/2020-12-31-traffic-analysis-quiz-04.pcap',
    'pcaps/2020-12-31-traffic-analysis-quiz-05.pcap',
    'pcaps/2020-12-31-traffic-analysis-quiz-06.pcap',
    'pcaps/2024-08-15-traffic-analysis-exercise.pcap',
    'pcaps/2024-09-04-traffic-analysis-exercise.pcap',
    'pcaps/2024-11-26-traffic-analysis-exercise.pcap',
    'pcaps/2025-01-22-traffic-analysis-exercise.pcap',
    'pcaps/2025-06-13-traffic-analysis-exercise.pcap',
    'pcaps/2026-01-31-traffic-analysis-exercise.pcap',
    'pcaps/2026-02-28-traffic-analysis-exercise.pcap'
]

headers = {'X-API-Key': '_OsuADwL45nXK2T3CAXY6F4xefz6StObNG2A00G0ZWM'}
total_events = 0
total_sent = 0

print('Analyzing all PCAPs...')
print('=' * 60)

for pcap_file in pcaps:
    try:
        a = PCAPAnalyzer(pcap_file)
        r = a.analyze()

        if 'error' in r:
            print(f'Error: {pcap_file} - {r.get("error")}')
            continue

        attacks = a.attacks
        events = a.get_events()
        total_events += len(events)

        if not events:
            print(f'{pcap_file.split("/")[1]}: 0 events (skipped)')
            continue

        sent = 0
        failed = 0
        for e in events[:30]:
            try:
                res = requests.post('http://127.0.0.1:5000/log', json=e, headers=headers, timeout=3)
                if res.status_code == 200:
                    sent += 1
                    total_sent += 1
                else:
                    failed += 1
            except Exception as ex:
                failed += 1

        name = pcap_file.split('/')[1][:30]
        print(f'{name}: {len(events)} events, {sent} sent')

    except Exception as ex:
        print(f'Error: {pcap_file} - {str(ex)[:50]}')

print('=' * 60)
print(f'Total events: {total_events}, Total sent: {total_sent}')