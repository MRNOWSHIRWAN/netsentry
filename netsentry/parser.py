"""Read flow records from CSV. Input is treated as untrusted: bad rows are counted, never fatal."""
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from pathlib import Path

MAX_BYTES = 20_000_000
MAX_ROWS = 200_000
REQUIRED = ('timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'bytes_out', 'action')
ACTIONS = {'allow', 'deny', 'auth_fail', 'auth_ok'}


@dataclass(frozen=True)
class Flow:
    time: datetime
    src: str
    dst: str
    port: int
    protocol: str
    bytes_out: int
    action: str


def parse_time(text):
    value = datetime.fromisoformat(text.strip().replace('Z', '+00:00'))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def parse_row(row):
    src = str(ipaddress.ip_address(row['src_ip'].strip()))
    dst = str(ipaddress.ip_address(row['dst_ip'].strip()))
    port = int(row['dst_port'])
    size = int(row['bytes_out'])
    action = row['action'].strip().lower()
    if not 0 <= port <= 65535 or size < 0 or action not in ACTIONS:
        raise ValueError('field out of range')
    return Flow(parse_time(row['timestamp']), src, dst, port, row['protocol'].strip().lower()[:8], size, action)


def load_flows(path):
    """Return (flows sorted by time, number of skipped rows). Raises ValueError for unusable files."""
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f'input exceeds {MAX_BYTES // 1_000_000} MB; split it first')
    flows, skipped = [], 0
    with path.open(newline='', encoding='utf-8') as stream:
        reader = csv.DictReader(stream)
        missing = [name for name in REQUIRED if name not in (reader.fieldnames or [])]
        if missing:
            raise ValueError('missing columns: ' + ', '.join(missing))
        for index, row in enumerate(reader):
            if index >= MAX_ROWS:
                raise ValueError(f'input exceeds {MAX_ROWS} rows; split it first')
            try:
                flows.append(parse_row(row))
            except (ValueError, KeyError, AttributeError, TypeError):
                skipped += 1
    flows.sort(key=lambda flow: flow.time)
    return flows, skipped
