"""Offline batch tests: only temporary traces and a mock benchmark are used."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BatchRoundsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='twitter-rounds-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scriptdir = self.root/'eval/twitter'
        scriptdir.mkdir(parents=True)
        self.runner = scriptdir/'a_total_single_policy_compare.sh'
        source = (ROOT/'eval/twitter/a_total_single_policy_compare.sh').read_text()
        self.runner.write_text(source.replace('POLICIES=(s3fifo)', 'POLICIES=(s3fifo fifo)'))
        (self.root/'scripts').mkdir()
        stub = scriptdir/'a_single_policy_compare.sh'
        stub.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
opts = dict(x.split('=', 1) for x in sys.argv[1:] if '=' in x)
with open(os.environ['MOCK_CALLS'], 'a') as f:
    f.write(json.dumps(dict(policy=sys.argv[2], **opts))+'\\n')
if os.environ.get('MOCK_FAIL') == 'true': sys.exit(7)
(pathlib.Path(opts['results_dir'])/'result.json').write_text(json.dumps(opts))
''')
        stub.chmod(0o755)
        (self.root/'policies').mkdir()
        for p in ['s3fifo', 'fifo']:
            binary = self.root/'policies'/f'cache_ext_{p}.out'
            binary.touch(); binary.chmod(0o755)
        traces = self.root/'traces'
        traces.mkdir()
        for name in ['init', 'bench', 'init_complete']:
            (traces/f'cluster24_{name}.txt').write_text('fixture\n')
        (traces/'.cluster24_bench.rsync_complete').touch()
        self.wss = self.root/'wss.csv'
        self.wss.write_text('cluster,leveldb_kv_bytes\n24,1000000000\n')
        bindir = self.root/'bin'
        bindir.mkdir()
        for name in ['sleep', 'ssh', 'rsync']:
            p = bindir/name
            p.write_text('#!/bin/sh\nexit '+('0' if name=='sleep' else '99')+'\n')
            p.chmod(0o755)
        self.calls = self.root/'calls.jsonl'
        self.output = self.root/'output with spaces'
        self.env = dict(os.environ, PATH=f'{bindir}:'+os.environ['PATH'],
                        REPETITIONS='3', TEST_MEMORY='true', MEMORY_INTERVAL='5',
                        RUNTIME='1200', WARMUP='45', WSS_CSV=str(self.wss),
                        LOCAL_TRACES_DIR=str(traces), RESULTS_DIR=str(self.output),
                        MOCK_CALLS=str(self.calls))

    def run_batch(self, *args, **env):
        return subprocess.run(['bash', str(self.runner), *args],
                              env=dict(self.env, **env), text=True,
                              capture_output=True, timeout=15)

    def test_two_rounds_preserve_diagnostics_and_baselines_per_repeat(self):
        r = self.run_batch('perf_mode=record')
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        calls = [json.loads(s) for s in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 12)  # two policies, three repeats, two modes
        self.assertEqual([Path(c['results_dir']).name for c in calls], ['perf','no_perf']*6)
        self.assertEqual(len({c['results_dir'] for c in calls}), 12)
        for c in calls:
            mode = Path(c['results_dir']).name
            self.assertEqual(c.get('skip_baseline'), 'true' if c['policy']=='fifo' else None)
            self.assertEqual(c['test_memory'], 'true')
            self.assertNotIn('test_leveldb_io', c)
            self.assertFalse(any(k.startswith('diagnostic_') for k in c))
            self.assertEqual(c['runtime'], '1200')
            self.assertEqual(c['perf_mode'], 'record' if mode=='perf' else 'none')
            self.assertEqual(c['test_perf'], 'true' if mode=='perf' else 'false')
            self.assertTrue((Path(c['results_dir'])/'command.sh').is_file())

    def test_removed_options_and_invalid_diagnostics_fail_before_output(self):
        for args in [('ablation=true',), ('ablation=false',), ('dry_run=true',),
                     ('perf_mode=bad',), ('diagnostic_refill_every=300',),
                     ('diagnostic_offcpu=true',), ('diagnostic_seconds=61',)]:
            with self.subTest(args=args):
                r = self.run_batch(*args)
                self.assertNotEqual(r.returncode, 0)
                self.assertFalse(self.calls.exists())
                self.assertFalse(self.output.exists())

    def test_failed_benchmark_stops_batch(self):
        r = self.run_batch(MOCK_FAIL='true')
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)

    def test_legacy_rounds_and_baseline_reuse_unchanged(self):
        r = self.run_batch(REPETITIONS='1')
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        calls = [json.loads(s) for s in self.calls.read_text().splitlines()]
        self.assertEqual([Path(c['results_dir']).name for c in calls], ['perf','no_perf']*2)
        self.assertEqual([c['perf_mode'] for c in calls], ['record','none']*2)
        self.assertEqual([c.get('skip_baseline') for c in calls], [None,None,'true','true'])

    def test_default_runtime_is_1200(self):
        self.env.pop('RUNTIME', None)
        r = self.run_batch(REPETITIONS='1')
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        calls = [json.loads(s) for s in self.calls.read_text().splitlines()]
        self.assertTrue(all(c['runtime']=='1200' for c in calls))


if __name__ == '__main__':
    unittest.main()
