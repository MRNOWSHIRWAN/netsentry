# NetSentry

A small Python command-line tool that reads network flow records you are authorized to analyze, flags suspicious patterns, writes a report, and explains each finding in plain language.

It uses only the Python standard library. It never touches the network, never scans anything and never contacts outside services. It only reads a CSV file.

## What it detects

| Finding | Pattern | Default threshold |
| --- | --- | --- |
| Port scan | One source tries many distinct ports on one host | 15 ports in 60 s |
| Failed-login burst | Many failed logins from one source, higher severity if a success follows | 8 failures in 300 s |
| Beaconing | Near-constant timing from one host to one destination and port | 8 events, under 10% timing jitter |
| Large outbound transfer | One source sends far more data than the others | 3 standard deviations and 10 MB |
| Cleartext service | Allowed traffic to FTP, Telnet, TFTP, POP3, IMAP or HTTP | any use |

Every finding includes what the pattern is, why it matters, how it can be harmless, a suggested next step and the evidence from your data.

## Quick start

Requires Python 3.9 or newer. No installs needed.

```bash
git clone https://github.com/MRNOWSHIRWAN/netsentry.git
cd netsentry
python -m netsentry samples/sample_flows.csv
```

Save a report, or get JSON for other tools:

```bash
python -m netsentry samples/sample_flows.csv --output report.md
python -m netsentry samples/sample_flows.csv --format json
```

Use it in automation. The exit code is 1 if a finding at the chosen severity or above exists, and 2 if the input cannot be read:

```bash
python -m netsentry flows.csv --fail-on high
```

See [samples/sample_report.md](samples/sample_report.md) for a full example report.

## Input format

A CSV file with these columns:

`timestamp,src_ip,dst_ip,dst_port,protocol,bytes_out,action`

- `timestamp`: ISO 8601, for example `2026-10-01T09:00:00Z` (no time zone means UTC)
- `src_ip`, `dst_ip`: IPv4 or IPv6 addresses
- `dst_port`: 0 to 65535
- `bytes_out`: bytes sent by the source
- `action`: `allow`, `deny`, `auth_fail` or `auth_ok`

Rows that cannot be parsed are counted and skipped, and the report shows how many. Input is limited to 20 MB and 200,000 rows. Convert your firewall, VPN or authentication logs to this shape first.

The sample data in `samples/` is synthetic. It uses documentation-only IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and is not real traffic. Regenerate it with `python samples/make_sample.py > samples/sample_flows.csv`.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover each detector (including near misses that must not trigger), input validation, report content and command-line behavior.

## Limits and responsible use

- Use it only on data from networks and systems you own or are authorized to review.
- Findings are heuristics. They are leads to check, not proof of an attack or of who is behind an address. Scanners, backups and monitoring tools can look the same.
- A report with no findings does not prove the data is clean.
- Thresholds are fixed defaults in `netsentry/detectors.py`. Tune them for your environment.
- Flow data and reports can reveal internal addresses and behavior. Keep them private and do not commit them (the `reports/` folder is git-ignored).

## Project layout

```
netsentry/parser.py     CSV loading and validation
netsentry/detectors.py  the five detectors
netsentry/explain.py    plain-language explanations
netsentry/report.py     Markdown and JSON output
netsentry/cli.py        command-line interface
samples/                synthetic sample data, generator and example report
tests/                  unittest suite
```
