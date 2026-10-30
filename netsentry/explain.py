"""Plain-language explanations: what it means, why it matters, how it can be benign, what to do."""
EXPLANATIONS = {
    'port_scan': ('Many different ports on one host were tried in a short time, which is how scanners map what a host exposes.',
                  'Scanning is often the first step before targeting a weak service.',
                  'Authorized vulnerability scanners, monitoring tools and misconfigured clients look the same.',
                  'Check whether the source is an approved scanner. If not, block or rate-limit it and confirm which of the probed ports are actually exposed.'),
    'auth_burst': ('Many failed logins came from one source in a few minutes, followed (for high severity) by a success.',
                   'Repeated failures suggest password guessing; a success after them may mean an account is compromised.',
                   'A user with an expired password or a broken script can cause the same pattern.',
                   'Review the account that succeeded, force a password reset if unexplained, and enable lockout or MFA on that service.'),
    'cleartext_service': ('A service that does not encrypt traffic was reachable and in use.',
                          'Anyone on the network path can read or alter credentials and data sent over it.',
                          'Internal lab devices or legacy equipment may still need it.',
                          'Move to the encrypted version (SSH, FTPS/SFTP, HTTPS, IMAPS/POP3S) or restrict access to a management network.'),
    'large_transfer': ('One source sent far more data out than the others.',
                       'Unusual outbound volume can indicate data being copied off the network.',
                       'Backups, software updates and media uploads are common benign causes.',
                       'Confirm the owner and purpose of the host, and compare with its normal backup or upload schedule.'),
    'beaconing': ('A host contacted the same destination at a near-constant interval.',
                  'Automated software that checks in with an outside server often behaves this way.',
                  'Update checks, monitoring agents and chat or sync apps are also regular.',
                  'Identify the process behind the traffic and check the destination against what the host should be talking to.'),
    'admin_exposure': ('A remote-administration service was reachable from many different sources.',
                       'SSH, RDP, SMB and VNC give deep control of a host, so every extra source that can reach them widens the attack surface.',
                       'A large admin team or a jump-host migration can legitimately broaden access for a while.',
                       'Restrict the service to the known admin hosts or a management network with firewall rules, and use a VPN or jump host for the rest.'),
    'repeated_denies': ('One source was blocked from the same destination and port many times and kept retrying.',
                        'Software that retries a blocked connection can be malware trying to reach a command server or a blocked exfiltration path.',
                        'A misconfigured application, a stale DNS entry or a health check pointed at a closed port causes the same pattern.',
                        'Identify the process behind the retries on the source host. If it is expected, fix the rule or the app configuration; if not, investigate the host.'),
}


def explain(kind):
    what, why, benign, action = EXPLANATIONS[kind]
    return {'what': what, 'why_it_matters': why, 'possible_benign_causes': benign, 'suggested_next_step': action}
