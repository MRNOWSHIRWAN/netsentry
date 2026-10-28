"""Read flow records from CSV. Input is treated as untrusted: bad rows are counted, never fatal."""
import csv
from collections import Counter
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
    """Build a Flow or raise ValueError naming why the row was skipped."""
    try:
        src = str(ipaddress.ip_address(row['src_ip'].strip()))
        dst = str(ipaddress.ip_address(row['dst_ip'].strip()))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError('bad IP address') from exc
    try:
        port = int(row['dst_port'])
        size = int(row['bytes_out'])
    except (TypeError, ValueError) as exc:
        raise ValueError('bad port or byte count') from exc
    if not 0 <= port <= 65535 or size < 0:
        raise ValueError('port or byte count out of range')
    try:
        action = row['action'].strip().lower()
    except AttributeError as exc:
        raise ValueError('unknown action') from exc
    if action not in ACTIONS:
        raise ValueError('unknown action')
    try:
        moment = parse_time(row['timestamp'])
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError('bad timestamp') from exc
    try:
        protocol = row['protocol'].strip().lower()[:8]
    except AttributeError as exc:
        raise ValueError('bad protocol') from exc
    return Flow(moment, src, dst, port, protocol, size, action)


def load_flows(path):
    """Return (flows sorted by time, skipped row count, skip reasons). Raises ValueError for unusable files."""
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f'input exceeds {MAX_BYTES // 1_000_000} MB; split it first')
    flows, skipped, reasons = [], 0, Counter()
    with path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        # Real exports add a BOM or vary header case/spacing; map cleaned names to the original ones.
        names = {}
        for name in reader.fieldnames or []:
            names.setdefault(name.strip().lower(), name)
        missing = [name for name in REQUIRED if name not in names]
        if missing:
            raise ValueError('missing columns: ' + ', '.join(missing))
        for index, row in enumerate(reader):
            if index >= MAX_ROWS:
                raise ValueError(f'input exceeds {MAX_ROWS} rows; split it first')
            try:
                flows.append(parse_row({key: row[names[key]] for key in REQUIRED}))
            except ValueError as exc:
                skipped += 1
                reasons[str(exc)] += 1
    flows.sort(key=lambda flow: flow.time)
    return flows, skipped, dict(reasons)


def filter_by_time(flows, since=None, until=None):
    """Keep flows at or after `since` and at or before `until` (datetimes)."""
    return [flow for flow in flows
            if (since is None or flow.time >= since) and (until is None or flow.time <= until)]
