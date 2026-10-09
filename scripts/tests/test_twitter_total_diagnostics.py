"""Offline full-runner tests: temp traces, mocked benchmark, network forbidden."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TotalDiagnosticsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='total-diagnostics-test-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        directory = self.root/'eval/twitter'
        directory.mkdir(parents=True)
        self.runner = directory/'a_total_single_policy_compare.sh'
        text = (ROOT/'eval/twitter'/self.runner.name).read_text()
        text = re.sub(r'^CLUSTERS=.*$', 'CLUSTERS=(24)', text, flags=re.M)
        text = re.sub(r'^POLICIES=.*$', 'POLICIES=(s3fifo fifo)', text, flags=re.M)
        self.runner.write_text(text)
        helper = self.root/'scripts'
        helper.mkdir()
        stub = directory/'a_single_policy_compare.sh'
        stub.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['MOCK_CALLS'], 'a') as f:
    f.write(json.dumps(args)+'\\n')
options = dict(arg.split('=', 1) for arg in args if '=' in arg)
if options['test_perf'] == os.environ.get('MOCK_FAIL_MODE'): sys.exit(7)
(pathlib.Path(options['results_dir'])/'result.json').write_text(json.dumps(options))
''')
        stub.chmod(0o755)
        policies = self.root/'policies'
        policies.mkdir()
        for policy in ('s3fifo', 'fifo'):
            path = policies/f'cache_ext_{policy}.out'
            path.touch()
            path.chmod(0o755)
        self.traces = self.root/'traces'
        self.traces.mkdir()
        for part in ('init', 'bench', 'init_complete'):
            (self.traces/f'cluster24_{part}.txt').write_text('fixture\n')
        (self.traces/'.cluster24_bench.rsync_complete').touch()
        self.csv = self.root/'wss.csv'
        self.csv.write_text('cluster,leveldb_kv_bytes\n24,104857600\n')
        bindir = self.root/'bin'
        bindir.mkdir()
        for name, command in (('sleep', 'exit 0'), ('ssh', 'exit 99'), ('rsync', 'exit 99')):
            path = bindir/name
            path.write_text('#!/bin/sh\n'+command+'\n')
            path.chmod(0o755)
        self.calls = self.root/'calls.jsonl'
        self.env = dict(os.environ, PATH=f'{bindir}:'+os.environ['PATH'], MOCK_CALLS=str(self.calls),
                        LOCAL_TRACES_DIR=str(self.traces), WSS_CSV=str(self.csv),
                        RESULTS_DIR=str(self.root/'results'), REPETITIONS='1', RUNTIME='900',
                        TEST_MEMORY='true', MEMORY_INTERVAL='5', WARMUP='45', CGROUP_PCT='70',
                        MAX_CGROUP_BYTES=str(12*1024**3))

    def run_total(self, *args, **env):
        return subprocess.run(['bash', str(self.runner), *args], env=dict(self.env, **env),
                              text=True, capture_output=True, timeout=15)

    def options(self):
        return [(args, dict(a.split('=', 1) for a in args if '=' in a))
                for args in map(json.loads, self.calls.read_text().splitlines())]

    def test_exact_user_command_forwarded_to_both_rounds(self):
        result = self.run_total('perf_mode=record')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        calls = self.options()
        self.assertEqual(len(calls), 4)
        for i, (args, opt) in enumerate(calls):
            self.assertEqual(args[:3], ['24', 's3fifo' if i < 2 else 'fifo', '70M'])
            self.assertEqual(opt['perf_mode'], 'record' if i % 2 == 0 else 'none')
            self.assertEqual(opt['test_perf'], 'true' if i % 2 == 0 else 'false')
            self.assertEqual(opt.get('skip_baseline', 'false'), 'true' if i >= 2 else 'false')
            run = Path(opt['results_dir'])
            self.assertEqual(run.name, 'perf' if i % 2 == 0 else 'no_perf')
            self.assertEqual(shlex.split((run/'command.sh').read_text())[1:], args)
        self.assertIn('perf=record no_perf=none', result.stdout)

    def test_default_modes_unchanged(self):
        result = self.run_total()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        for i, (_, opt) in enumerate(self.options()):
            self.assertEqual(opt['perf_mode'], 'record' if i % 2 == 0 else 'none')
            self.assertNotIn('diagnostic_ops', opt)
            self.assertNotIn('sst_sample_every', opt)
            self.assertNotIn('test_leveldb_io', opt)

    def test_bad_args_fail_before_cleanup_or_benchmark(self):
        sentinel = self.traces/'cluster99_bench.txt'
        sentinel.write_text('must survive\n')
        for args in [('sst_sampe_every=256',), ('perf_mode=none',), ('perf_mode=bad',),
                     ('sst_sample_every=-1',), ('diagnostic_seconds=0',),
                     ('diagnostic_seconds=61',), ('diagnostic_frequency=200',),
                     ('diagnostic_ops=10:20,15:30',), ('diagnostic_ops=a:b',),
                     ('diagnostic_offcpu=true',), ('diagnostic_offcpu=yes',),
                     ('diagnostic_refill_every=512',), ('diagnostic_refill_every=300',),
                     ('sst_sample_every=256', 'test_leveldb_io=false'), ('results_dir=',)]:
            with self.subTest(args=args):
                result = self.run_total(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('[Error]', result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertTrue(sentinel.exists())
                self.assertFalse((self.root/'results').exists())

    def test_result_directory_and_benchmark_failure(self):
        out = self.root/'custom output'
        result = self.run_total(f'results_dir={out}', 'perf_mode=tracepoint', MOCK_FAIL_MODE='false')
        self.assertEqual(result.returncode, 7, result.stdout+result.stderr)
        self.assertEqual(len(self.options()), 2)
        self.assertTrue((out/'cluster24/s3fifo/repeat1/perf/command.sh').is_file())
        self.assertEqual(self.options()[0][1]['perf_mode'], 'tracepoint')


if __name__ == '__main__':
    unittest.main()
