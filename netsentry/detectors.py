"""Heuristic detectors. Each returns Finding objects; thresholds are parameters, not secrets."""
from collections import defaultdict
from dataclasses import dataclass, field
from statistics import mean, pstdev

CLEARTEXT_PORTS = {21: 'FTP', 23: 'Telnet', 69: 'TFTP', 110: 'POP3', 143: 'IMAP', 80: 'HTTP'}
RISKY_ADMIN_PORTS = {22: 'SSH', 3389: 'RDP', 445: 'SMB', 5900: 'VNC'}


@dataclass
class Finding:
    kind: str
    severity: str  # high, medium, low
    source: str
    summary: str
    evidence: dict = field(default_factory=dict)


def port_scans(flows, min_ports=15, window_seconds=60):
    """One source touching many distinct ports on a host within a short window."""
    findings, by_pair = [], defaultdict(list)
    for flow in flows:
        by_pair[(flow.src, flow.dst)].append(flow)
    for (src, dst), items in by_pair.items():
        start, best, best_start = 0, 0, 0
        for end, flow in enumerate(items):
            while (flow.time - items[start].time).total_seconds() > window_seconds:
                start += 1
            count = len({f.port for f in items[start:end + 1]})
            if count > best:
                best, best_start = count, start
        if best >= min_ports:
            findings.append(Finding('port_scan', 'high', src,
                                    f'{src} probed {best} distinct ports on {dst} within {window_seconds}s',
                                    {'target': dst, 'distinct_ports': best, 'first_seen': items[best_start].time.isoformat()}))
    return findings


def auth_bursts(flows, min_failures=8, window_seconds=300):
    """Many failed logins from one source; escalate if a success follows."""
    findings, by_src = [], defaultdict(list)
    for flow in flows:
        if flow.action in ('auth_fail', 'auth_ok'):
            by_src[flow.src].append(flow)
    for src, items in by_src.items():
        fails = [f for f in items if f.action == 'auth_fail']
        start, best, best_start, best_end = 0, 0, 0, 0
        for end, flow in enumerate(fails):
            while (flow.time - fails[start].time).total_seconds() > window_seconds:
                start += 1
            if end - start + 1 > best:
                best, best_start, best_end = end - start + 1, start, end
        if best >= min_failures:
            window_end = fails[best_end].time
            success = any(f.action == 'auth_ok' and f.time >= window_end for f in items)
            findings.append(Finding('auth_burst', 'high' if success else 'medium', src,
                                    f'{src} had {best} failed logins in {window_seconds}s' +
                                    (' and then a successful login' if success else ''),
                                    {'failures_in_window': best, 'success_followed': success,
                                     'targets': sorted({f.dst for f in fails[best_start:best_end + 1]})}))
    return findings


def cleartext_services(flows):
    """Allowed traffic to services that send credentials or data unencrypted."""
    seen = defaultdict(lambda: defaultdict(int))
    for flow in flows:
        if flow.action == 'allow' and flow.port in CLEARTEXT_PORTS:
            seen[(flow.dst, flow.port)][flow.src] += 1
    return [Finding('cleartext_service', 'low' if port == 80 else 'medium', dst,
                    f'{CLEARTEXT_PORTS[port]} (port {port}) on {dst} was used by {len(sources)} source(s)',
                    {'port': port, 'sources': sorted(sources)[:10]})
            for (dst, port), sources in sorted(seen.items())]


def large_transfers(flows, z_cutoff=3.0, min_bytes=10_000_000):
    """Per-source outbound totals far above the typical source."""
    totals = defaultdict(int)
    for flow in flows:
        if flow.action == 'allow':
            totals[flow.src] += flow.bytes_out
    if len(totals) < 4:
        return []
    values = list(totals.values())
    avg, spread = mean(values), pstdev(values)
    if spread == 0:
        return []
    return [Finding('large_transfer', 'medium', src,
                    f'{src} sent {size / 1e6:.1f} MB, {((size - avg) / spread):.1f} standard deviations above the average source',
                    {'bytes_out': size, 'average_bytes': int(avg)})
            for src, size in sorted(totals.items()) if size >= min_bytes and (size - avg) / spread >= z_cutoff]


def beaconing(flows, min_events=8, max_jitter=0.1):
    """Very regular connection timing from one source to one destination:port (possible automated check-in)."""
    findings, groups = [], defaultdict(list)
    for flow in flows:
        if flow.action == 'allow':
            groups[(flow.src, flow.dst, flow.port)].append(flow.time.timestamp())
    for (src, dst, port), times in groups.items():
        if len(times) < min_events:
            continue
        gaps = [b - a for a, b in zip(times, times[1:])]
        gap_avg = mean(gaps)
        if gap_avg >= 5 and pstdev(gaps) / gap_avg <= max_jitter:
            findings.append(Finding('beaconing', 'medium', src,
                                    f'{src} contacted {dst}:{port} {len(times)} times at a steady ~{gap_avg:.0f}s interval',
                                    {'target': dst, 'port': port, 'events': len(times), 'interval_seconds': round(gap_avg, 1)}))
    return findings


def run_all(flows):
    order = {'high': 0, 'medium': 1, 'low': 2}
    findings = port_scans(flows) + auth_bursts(flows) + large_transfers(flows) + beaconing(flows) + cleartext_services(flows)
    return sorted(findings, key=lambda f: (order[f.severity], f.kind, f.source))
