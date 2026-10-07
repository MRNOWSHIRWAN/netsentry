# NetSentry report

> Heuristic findings from the supplied data only. They are leads to verify, not proof of an attack or of who is responsible. Use only data you are authorized to analyze.

- Flows analyzed: **365** (rows skipped as invalid: 0)
- Time range (UTC): 2026-10-01T09:00:05+00:00 to 2026-10-01T10:00:00+00:00
- Findings: 2 high, 3 medium

## 1. [HIGH] 203.0.113.77 had 12 failed logins in 300s and then a successful login

- **What this is:** Many failed logins came from one source in a few minutes, followed (for high severity) by a success.
- **Why it matters:** Repeated failures suggest password guessing; a success after them may mean an account is compromised.
- **Could be harmless if:** A user with an expired password or a broken script can cause the same pattern.
- **Suggested next step:** Review the account that succeeded, force a password reset if unexplained, and enable lockout or MFA on that service.
- **Evidence:** failures_in_window=12, success_followed=True, targets=['192.0.2.5']

## 2. [HIGH] 203.0.113.50 probed 40 distinct ports on 192.0.2.5 within 60s

- **What this is:** Many different ports on one host were tried in a short time, which is how scanners map what a host exposes.
- **Why it matters:** Scanning is often the first step before targeting a weak service.
- **Could be harmless if:** Authorized vulnerability scanners, monitoring tools and misconfigured clients look the same.
- **Suggested next step:** Check whether the source is an approved scanner. If not, block or rate-limit it and confirm which of the probed ports are actually exposed.
- **Evidence:** target=192.0.2.5, distinct_ports=40, first_seen=2026-10-01T09:20:01+00:00

## 3. [MEDIUM] 192.0.2.31 contacted 198.51.100.99:8443 10 times at a steady ~60s interval

- **What this is:** A host contacted the same destination at a near-constant interval.
- **Why it matters:** Automated software that checks in with an outside server often behaves this way.
- **Could be harmless if:** Update checks, monitoring agents and chat or sync apps are also regular.
- **Suggested next step:** Identify the process behind the traffic and check the destination against what the host should be talking to.
- **Evidence:** target=198.51.100.99, port=8443, events=10, interval_seconds=60.0

## 4. [MEDIUM] FTP (port 21) on 192.0.2.8 was used by 1 source(s)

- **What this is:** A service that does not encrypt traffic was reachable and in use.
- **Why it matters:** Anyone on the network path can read or alter credentials and data sent over it.
- **Could be harmless if:** Internal lab devices or legacy equipment may still need it.
- **Suggested next step:** Move to the encrypted version (SSH, FTPS/SFTP, HTTPS, IMAPS/POP3S) or restrict access to a management network.
- **Evidence:** port=21, sources=['192.0.2.12']

## 5. [MEDIUM] 192.0.2.14 sent 900.2 MB, 5.6 standard deviations above the average source

- **What this is:** One source sent far more data out than the others.
- **Why it matters:** Unusual outbound volume can indicate data being copied off the network.
- **Could be harmless if:** Backups, software updates and media uploads are common benign causes.
- **Suggested next step:** Confirm the owner and purpose of the host, and compare with its normal backup or upload schedule.
- **Evidence:** bytes_out=900171151, average_bytes=28319766
