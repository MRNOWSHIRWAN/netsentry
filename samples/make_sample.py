"""Generate synthetic, fictional sample data (documentation IP ranges only). Not real traffic."""
import csv
from datetime import datetime, timedelta, timezone
import random
import sys

random.seed(42)
start = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
rows = []


def add(offset, src, dst, port, proto, size, action):
    rows.append([(start + timedelta(seconds=offset)).isoformat(), src, dst, port, proto, size, action])


for i in range(300):  # normal office traffic
    add(i * 11 + random.randint(0, 5), f'192.0.2.{random.randint(10, 40)}', '198.51.100.20', random.choice([443, 443, 443, 53]), 'tcp', random.randint(500, 40000), 'allow')
for port in range(1, 41):  # port scan from 203.0.113.50
    add(1200 + port, '203.0.113.50', '192.0.2.5', port, 'tcp', 60, 'deny' if port != 22 else 'allow')
for i in range(12):  # failed logins then success
    add(2000 + i * 8, '203.0.113.77', '192.0.2.5', 22, 'tcp', 300, 'auth_fail')
add(2110, '203.0.113.77', '192.0.2.5', 22, 'tcp', 300, 'auth_ok')
for i in range(10):  # beaconing every 60 seconds
    add(3000 + i * 60, '192.0.2.31', '198.51.100.99', 8443, 'tcp', 400, 'allow')
add(3500, '192.0.2.12', '192.0.2.8', 21, 'tcp', 2000, 'allow')  # cleartext FTP
add(3600, '192.0.2.14', '198.51.100.45', 443, 'tcp', 900_000_000, 'allow')  # large upload
writer = csv.writer(sys.stdout, lineterminator='\n')
writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'bytes_out', 'action'])
writer.writerows(sorted(rows))
