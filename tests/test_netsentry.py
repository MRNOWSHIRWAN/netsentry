import csv
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from netsentry import cli, detectors, parser, report
from netsentry.parser import Flow

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
SAMPLE = Path(__file__).resolve().parent.parent / 'samples' / 'sample_flows.csv'


def flow(sec, src='192.0.2.1', dst='192.0.2.9', port=443, size=100, action='allow'):
    return Flow(T0 + timedelta(seconds=sec), src, dst, port, 'tcp', size, action)


class DetectorTests(unittest.TestCase):
    def test_port_scan_reports_the_full_scan_size(self):
        found = detectors.port_scans([flow(i, port=i + 1) for i in range(40)])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].evidence['distinct_ports'], 40)

    def test_slow_port_touches_are_not_a_scan(self):
        self.assertEqual(detectors.port_scans([flow(i * 30, port=i + 1) for i in range(40)]), [])

    def test_auth_burst_escalates_when_a_success_follows(self):
        fails = [flow(i, action='auth_fail', port=22) for i in range(10)]
        self.assertEqual(detectors.auth_bursts(fails)[0].severity, 'medium')
        self.assertEqual(detectors.auth_bursts(fails + [flow(20, action='auth_ok', port=22)])[0].severity, 'high')
        self.assertEqual(detectors.auth_bursts(fails[:5]), [])

    def test_success_before_the_failures_does_not_escalate(self):
        rows = [flow(0, action='auth_ok', port=22)] + [flow(10 + i, action='auth_fail', port=22) for i in range(10)]
        self.assertEqual(detectors.auth_bursts(rows)[0].severity, 'medium')

    def test_beaconing_needs_regular_timing(self):
        regular = [flow(i * 60, port=8443) for i in range(10)]
        irregular = [flow(t, port=8443) for t in (0, 7, 100, 130, 400, 410, 900, 1500, 1520, 3000)]
        self.assertEqual(len(detectors.beaconing(regular)), 1)
        self.assertEqual(detectors.beaconing(irregular), [])

    def test_cleartext_only_counts_allowed_traffic(self):
        self.assertEqual(len(detectors.cleartext_services([flow(0, port=23)])), 1)
        self.assertEqual(detectors.cleartext_services([flow(0, port=23, action='deny')]), [])

    def test_large_transfer_needs_an_outlier_and_enough_sources(self):
        rows = [flow(i, src=f'192.0.2.{i + 1}', size=1000) for i in range(10)] + [flow(50, src='192.0.2.99', size=500_000_000)]
        self.assertEqual([f.source for f in detectors.large_transfers(rows)], ['192.0.2.99'])
        self.assertEqual(detectors.large_transfers(rows[:2]), [])


class ParserTests(unittest.TestCase):
    def write(self, folder, lines):
        path = Path(folder) / 'f.csv'
        path.write_text('\n'.join(lines) + '\n')
        return path

    HEADER = 'timestamp,src_ip,dst_ip,dst_port,protocol,bytes_out,action'

    def test_bad_rows_are_counted_and_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write(folder, [self.HEADER,
                '2026-10-01T09:00:00Z,192.0.2.1,192.0.2.2,443,tcp,10,allow',
                'garbage,not-an-ip,192.0.2.2,443,tcp,10,allow',
                '2026-10-01T09:00:01Z,192.0.2.1,192.0.2.2,99999,tcp,10,allow',
                '2026-10-01T09:00:02Z,192.0.2.1,192.0.2.2,443,tcp,-5,allow',
                '2026-10-01T09:00:03Z,192.0.2.1,192.0.2.2,443,tcp,10,hack'])
            flows, skipped = parser.load_flows(path)
            self.assertEqual((len(flows), skipped), (1, 4))

    def test_missing_columns_and_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'missing columns'):
                parser.load_flows(self.write(folder, ['timestamp,src_ip', 'x,y']))
            path = self.write(folder, [self.HEADER] + ['2026-10-01T09:00:00Z,192.0.2.1,192.0.2.2,443,tcp,1,allow'] * 3)
            original = parser.MAX_ROWS
            parser.MAX_ROWS = 2
            try:
                with self.assertRaisesRegex(ValueError, 'rows'):
                    parser.load_flows(path)
            finally:
                parser.MAX_ROWS = original

    def test_naive_timestamps_are_treated_as_utc_and_sorted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.write(folder, [self.HEADER,
                '2026-10-01T09:00:05,192.0.2.1,192.0.2.2,443,tcp,1,allow',
                '2026-10-01T09:00:01,192.0.2.1,192.0.2.2,443,tcp,1,allow'])
            flows, _ = parser.load_flows(path)
            self.assertLess(flows[0].time, flows[1].time)
            self.assertEqual(flows[0].time.tzinfo, timezone.utc)


class EndToEndTests(unittest.TestCase):
    def test_sample_data_produces_each_expected_finding(self):
        flows, skipped = parser.load_flows(SAMPLE)
        kinds = sorted(f.kind for f in detectors.run_all(flows))
        self.assertEqual(kinds, ['auth_burst', 'beaconing', 'cleartext_service', 'large_transfer', 'port_scan'])
        self.assertEqual(skipped, 0)

    def test_markdown_and_json_reports_explain_findings(self):
        flows, skipped = parser.load_flows(SAMPLE)
        findings = detectors.run_all(flows)
        text = report.to_markdown(flows, skipped, findings)
        self.assertIn('Suggested next step', text)
        self.assertIn('not proof of an attack', text)
        data = json.loads(report.to_json(flows, skipped, findings))
        self.assertEqual(data['summary']['flows_analyzed'], len(flows))
        self.assertTrue(all('explanation' in item for item in data['findings']))

    def test_empty_data_reports_no_findings_without_claiming_clean(self):
        self.assertIn('does not prove', report.to_markdown([], 0, []))

    def test_cli_exit_codes_and_output_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'r.md'
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main([str(SAMPLE), '--output', str(out)]), 0)
                self.assertEqual(cli.main([str(SAMPLE), '--fail-on', 'high']), 1)
            self.assertIn('NetSentry report', out.read_text())
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(cli.main([str(SAMPLE), '--output', str(SAMPLE)]), 2)
                self.assertEqual(cli.main([str(Path(folder) / 'missing.csv')]), 2)
            self.assertIn('netsentry:', err.getvalue())
            self.assertGreater(SAMPLE.stat().st_size, 1000)  # the input was not overwritten


if __name__ == '__main__':
    unittest.main()
