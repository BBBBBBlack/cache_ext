"""Offline checks; never launch a benchmark or read a live cgroup."""
import itertools
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MemoryPollTest(unittest.TestCase):
    def test_resolution_matrix(self):
        for requested, memory in itertools.product(
                ('auto', 'true', 'false'), ('true', 'false')):
            with self.subTest(requested=requested, memory=memory):
                script = '''set -eu
source eval/leveldb_io_monitor.sh
MEMORY_POLL="$1" TEST_MEMORY="$2"
resolve_memory_poll
echo "$MEMORY_POLL_ENABLED"
'''
                run = subprocess.run(['bash', '-c', script, 'test', requested, memory],
                                     cwd=ROOT, text=True, capture_output=True, check=True)
                expected = memory == 'true' and requested == 'true'
                self.assertEqual(run.stdout.strip(), str(expected).lower())

    def test_invalid_mode(self):
        run = subprocess.run(['bash', '-c',
            'source eval/leveldb_io_monitor.sh; MEMORY_POLL=invalid; resolve_memory_poll'],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)

    def test_no_retired_probe_defaults(self):
        source = (ROOT/'eval/twitter/a_total_single_policy_compare.sh').read_text()
        self.assertIn('PERF_RUN_MODE=record', source)
        for removed in ('SST_SAMPLE_EVERY=', 'DIAGNOSTIC_OFFCPU=', 'DIAGNOSTIC_REFILL_EVERY='):
            self.assertNotIn(removed, source)


if __name__ == '__main__':
    unittest.main()
