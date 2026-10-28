"""Render findings as Markdown or JSON. Evidence is shown as-is from the input; no network lookups."""
import json
from collections import Counter

from .explain import explain

NOTE = ('Heuristic findings from the supplied data only. They are leads to verify, not proof of an attack '
        'or of who is responsible. Use only data you are authorized to analyze.')


def summary(flows, skipped, findings, reasons=None):
    info = {'flows_analyzed': len(flows), 'rows_skipped': skipped,
            'time_range': [flows[0].time.isoformat(), flows[-1].time.isoformat()] if flows else None,
            'findings_by_severity': dict(Counter(f.severity for f in findings))}
    if reasons:
        info['skip_reasons'] = dict(reasons)
    return info


def to_json(flows, skipped, findings, reasons=None):
    return json.dumps({'note': NOTE, 'summary': summary(flows, skipped, findings, reasons),
                       'findings': [{**vars(f), 'explanation': explain(f.kind)} for f in findings]}, indent=2)


def to_markdown(flows, skipped, findings, reasons=None):
    info = summary(flows, skipped, findings)
    skipped_text = str(skipped)
    if reasons:
        skipped_text += ' (' + ', '.join(f'{reason}: {count}' for reason, count in sorted(reasons.items())) + ')'
    lines = ['# NetSentry report', '', f'> {NOTE}', '',
             f"- Flows analyzed: **{info['flows_analyzed']}** (rows skipped as invalid: {skipped_text})",
             f"- Time range (UTC): {' to '.join(info['time_range']) if info['time_range'] else 'none'}",
             '- Findings: ' + (', '.join(f'{n} {sev}' for sev, n in info['findings_by_severity'].items()) or 'none'), '']
    if not findings:
        lines.append('No suspicious patterns matched the current thresholds. That does not prove the data is clean.')
    for number, finding in enumerate(findings, 1):
        why = explain(finding.kind)
        lines += [f'## {number}. [{finding.severity.upper()}] {finding.summary}', '',
                  f'- **What this is:** {why["what"]}', f'- **Why it matters:** {why["why_it_matters"]}',
                  f'- **Could be harmless if:** {why["possible_benign_causes"]}',
                  f'- **Suggested next step:** {why["suggested_next_step"]}',
                  '- **Evidence:** ' + ', '.join(f'{k}={v}' for k, v in finding.evidence.items()), '']
    return '\n'.join(lines)
