import argparse
from pathlib import Path
import sys

from . import __version__
from .detectors import run_all
from .parser import load_flows
from .report import to_json, to_markdown


def main(argv=None):
    parser = argparse.ArgumentParser(prog='netsentry', description="Analyze authorized network flow data, flag suspicious patterns and explain them.")
    parser.add_argument('input', type=Path, help='CSV of flow records (see samples/sample_flows.csv)')
    parser.add_argument('--format', choices=('markdown', 'json'), default='markdown')
    parser.add_argument('--output', type=Path, help='write the report here instead of printing it')
    parser.add_argument('--fail-on', choices=('high', 'medium', 'low'),
                        help='exit with status 1 if a finding at this severity or above exists (for automation)')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        flows, skipped = load_flows(args.input)
        findings = run_all(flows)
        text = (to_json if args.format == 'json' else to_markdown)(flows, skipped, findings)
        if args.output:
            if args.output.resolve() == args.input.resolve():
                raise ValueError('output must differ from the input file')
            args.output.write_text(text + '\n', encoding='utf-8')
            print(f'Report saved to {args.output}: {len(findings)} finding(s), {skipped} row(s) skipped.')
        else:
            print(text)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f'netsentry: cannot analyze input: {exc}', file=sys.stderr)
        return 2
    if args.fail_on:
        rank = {'high': 0, 'medium': 1, 'low': 2}
        if any(rank[f.severity] <= rank[args.fail_on] for f in findings):
            return 1
    return 0
