"""Offline checks: perf, benchmark processes and machine setup are never run."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SINGLE = (HERE / "a_single_policy_compare.sh").read_text()
PARSER = SINGLE.split('CLUSTER="$1"', 1)[1].split("\nITERATIONS=1", 1)[0]
PARSER = 'CLUSTER="$1"' + PARSER
NAMING = SINGLE.split("sanitize_filename_component() {", 1)[1].split(
    '\necho "[Info] Twitter cluster:', 1
)[0]
NAMING = "sanitize_filename_component() {" + NAMING
SAVE_METADATA = SINGLE[SINGLE.index('python3 - "$RESULT_FILE" "$PERF_MODE"'):]


def function(name):
    return re.search(rf"^{name}\(\) \{{\n.*?^\}}", SINGLE, re.M | re.S).group()


MONITORS = "\n".join(
    function(name)
    for name in (
        "stop_pcache_monitor", "stop_perf_monitor",
        "start_pcache_monitor", "start_perf_monitor",
    )
)


class MonitorModesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="twitter-mode-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, MOCK_ROOT=str(self.root))

    def run_single_parts(self, *args):
        script = r'''
set -eu -o pipefail
usage() { exit 2; }
RESULTS_PATH="$MOCK_ROOT"
BASE_DIR="$(pwd)"
''' + PARSER + "\n" + NAMING + "\n" + MONITORS + r'''
source "$BASE_DIR/eval/leveldb_io_monitor.sh"
resolve_memory_poll
find_run_leveldb_pid_for_cgroup() { printf '%s\n' "$$"; }
sleep() { :; }
sudo() {
    printf '%s\n' "$*" >> "$MOCK_ROOT/calls"
    if [ "$1 $2" = "perf record" ]; then
        while [ "$1" != "-o" ]; do shift; done
        printf 'mock perf data\n' > "$2"
    fi
}
PCACHE_MONITOR_PID=""
PERF_MONITOR_PID=""
PERF_RECORD_SECONDS=60
PERF_START_DELAY_SECONDS="$WARMUP_RUNTIME_SECONDS"
PCACHE_EVENTS="filemap:mm_filemap_add_to_page_cache,filemap:mm_filemap_add_to_page_cache_prefetch"
start_pcache_monitor baseline btest
start_perf_monitor baseline btest
if [ -n "$PCACHE_MONITOR_PID" ]; then wait "$PCACHE_MONITOR_PID"; fi
if [ -n "$PERF_MONITOR_PID" ]; then wait "$PERF_MONITOR_PID"; fi
printf '[{"config": {}, "results": {}}]\n' > "$RESULT_FILE"
''' + SAVE_METADATA
        return subprocess.run(
            ["bash", "-c", script, "mode-test", "34", "s3fifo", "3G", *args],
            env=self.env, text=True, capture_output=True, timeout=10,
        )

    def test_each_mode_calls_only_its_monitors_and_saves_metadata(self):
        for mode, record, tracepoint in (
            ("none", False, False), ("record", True, False),
            ("tracepoint", False, True), ("both", True, True),
        ):
            with self.subTest(mode=mode):
                calls = self.root / "calls"
                if calls.exists():
                    calls.unlink()
                result = self.run_single_parts(f"perf_mode={mode}", "test_memory=true")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                invoked = calls.read_text().splitlines() if calls.exists() else []
                self.assertEqual(sum(s.startswith("perf record ") for s in invoked), int(record))
                self.assertEqual(sum(s.startswith("perf stat ") for s in invoked), int(tracepoint))
                self.assertEqual(sum(s.startswith("perf report ") for s in invoked), int(record))
                prefix = "twitter_spc_s3fifo_cluster34_3G"
                path = self.root / f"{prefix}_{mode}.json"
                config = json.loads(path.read_text())[0]["config"]
                self.assertEqual(config["perf_mode"], mode)
                self.assertEqual(config["test_perf_record"], record)
                self.assertEqual(config["test_tracepoint"], tracepoint)
                self.assertTrue(config["test_memory"])
                self.assertEqual((self.root / f"{prefix}.json").read_text(), path.read_text())
                self.assertEqual((self.root / f"{prefix}_perf_{mode}_baseline.data").exists(), record)
                self.assertEqual((self.root / f"{prefix}_pcache_{mode}_baseline.log").exists(), tracepoint)
        self.assertEqual(len(list(self.root.glob("*_3G_*.json"))), 4)

    def test_legacy_flags_and_explicit_mode_precedence(self):
        for args, expected in (
            ((), "none"), (("test_perf=true",), "both"),
            (("test_perf=false",), "none"), (("--test-perf",), "both"),
            (("test_perf=true", "perf_mode=record"), "record"),
            (("perf_mode=tracepoint", "test_perf=true"), "tracepoint"),
            (("perf_mode=both", "test_perf=false"), "both"),
        ):
            with self.subTest(args=args):
                result = self.run_single_parts(*args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                config = json.loads((self.root / "twitter_spc_s3fifo_cluster34_3G.json").read_text())[0]["config"]
                self.assertEqual(config["perf_mode"], expected)

    def test_invalid_mode_fails_before_monitoring(self):
        for mode in ("", "invalid", "TRUE"):
            result = self.run_single_parts(f"perf_mode={mode}")
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "calls").exists())

    def test_custom_output_path_and_readahead_tag(self):
        output = self.root / "results with spaces"
        output.mkdir()
        result = self.run_single_parts(
            "perf_mode=none", f"results_dir={output}", "readahead_kb=64",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((output / "twitter_spc_s3fifo_cluster34_3G_ra64KB_none.json").exists())


    def test_snapshots_follow_test_memory(self):
        for value in ("true", "false"):
            result = self.run_single_parts("perf_mode=none", f"test_memory={value}")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            path = self.root / "twitter_spc_s3fifo_cluster34_3G_none.json"
            config = json.loads(path.read_text())[0]["config"]
            self.assertEqual(config["test_memory_snapshots"], value == "true")
            self.assertNotIn("test_leveldb_io", config)


    def test_invalid_diagnostics(self):
        for args in (('sst_sample_every=-1',), ('diagnostic_seconds=0',),
                     ('diagnostic_frequency=200',), ('diagnostic_ops=10:5',),
                     ('sst_sample_every=256', 'test_leveldb_io=false'),
                     ('diagnostic_offcpu=true',), ('diagnostic_offcpu=invalid',),
                     ('diagnostic_refill_every=512',), ('diagnostic_refill_every=300',),
                     ('diagnostic_refill_every=000',)):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_single_parts(*args).returncode, 0)

    def test_retired_options_rejected_even_when_disabled(self):
        for option in ("test_leveldb_io=false", "sst_sample_every=0",
                       "diagnostic_offcpu=false", "diagnostic_refill_every=0"):
            result = self.run_single_parts(option)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root/'calls').exists())


class MatrixRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="twitter-matrix-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        scripts = self.root / "eval/twitter"
        scripts.mkdir(parents=True)
        self.runner = scripts / "a_total_single_policy_compare2.sh"
        shutil.copyfile(HERE / self.runner.name, self.runner)
        stub = scripts / "a_single_policy_compare.sh"
        stub.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["MOCK_CALLS"], "a") as f:
    f.write(json.dumps(args) + "\\n")
options = dict(arg.split("=", 1) for arg in args if "=" in arg)
if options["test_perf"] == os.environ.get("MOCK_FAIL_MODE"):
    sys.exit(7)
out = pathlib.Path(options["results_dir"])
(out / "result.json").write_text(json.dumps(options))
print("mock benchmark complete")
''')
        stub.chmod(0o755)
        policies = self.root / "policies"
        policies.mkdir()
        policy = policies / "cache_ext_s3fifo.out"
        policy.touch()
        policy.chmod(0o755)
        traces = self.root / "traces"
        traces.mkdir()
        for name in ("init", "bench", "init_complete"):
            (traces / f"cluster34_{name}.txt").write_text("fixture\n")
        (traces / ".cluster34_bench.rsync_complete").touch()
        bindir = self.root / "bin"
        bindir.mkdir()
        sleep = bindir / "sleep"
        sleep.write_text("#!/bin/sh\nexit 0\n")
        sleep.chmod(0o755)
        # Guard against future runner changes ever reaching real SSH/rsync.
        for command in ("ssh", "rsync"):
            guard = bindir / command
            guard.write_text("#!/bin/sh\necho 'unexpected network command in offline test' >&2\nexit 99\n")
            guard.chmod(0o755)
        self.calls = self.root / "calls.jsonl"
        self.env = dict(
            os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
            LOCAL_TRACES_DIR=str(traces), RESULTS_DIR=str(self.root / "output with spaces"),
            MOCK_CALLS=str(self.calls),
            REPETITIONS="1", CGROUP_SIZE="3G", TEST_MEMORY="true",
            RUNTIME="240", WARMUP="30", MEMORY_INTERVAL="2", READAHEAD_KB="64",
            TRACE_NR_OP_MODE="ignore-nr-op", CACHE_EXT_CGROUP="ce_test",
            BASELINE_CGROUP="base_test",
        )

    def run_matrix(self, **overrides):
        return subprocess.run(
            ["bash", str(self.runner)], env=dict(self.env, **overrides),
            text=True, capture_output=True, timeout=10,
        )

    def read_calls(self):
        return [json.loads(s) for s in self.calls.read_text().splitlines()]

    def test_order_repetitions_and_control_variables(self):
        result = self.run_matrix(REPETITIONS="2")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.read_calls()
        self.assertEqual(len(calls), 4)
        shared = None
        output_dirs = set()
        for index, args in enumerate(calls):
            self.assertEqual(args[:4], ["34", "s3fifo", "3G", "ignore-nr-op"])
            options = dict(arg.split("=", 1) for arg in args if "=" in arg)
            self.assertEqual(options.pop("test_perf"), ("true", "false")[index % 2])
            directory = options.pop("results_dir")
            self.assertNotIn(directory, output_dirs)
            output_dirs.add(directory)
            for name in ("command.sh", "console.log", "result.json"):
                self.assertTrue((Path(directory) / name).is_file())
            if shared is None:
                shared = options
            self.assertEqual(options, shared)
        self.assertEqual(shared["runtime"], "240")
        self.assertEqual(shared["warmup"], "30")
        self.assertEqual(shared["memory_interval"], "2")
        self.assertEqual(shared["readahead_kb"], "64")
        self.assertEqual(shared["test_memory"], "true")

    def test_failed_benchmark_stops_the_matrix(self):
        result = self.run_matrix(MOCK_FAIL_MODE="false")
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertEqual(len(self.read_calls()), 2)

    def test_existing_results_follow_current_reuse_setting(self):
        directory = Path(self.env["RESULTS_DIR"]) / "cluster34/s3fifo/repeat1/perf"
        directory.mkdir(parents=True)
        result = directory / "result.json"
        result.write_text("existing result\n")
        completed = self.run_matrix()
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(len(self.read_calls()), 2)
        self.assertEqual(json.loads(result.read_text())["test_perf"], "true")

    def test_invalid_configuration_never_launches_a_benchmark(self):
        for overrides in (
            {"REPETITIONS": "0"}, {"TEST_MEMORY": "invalid"},
            {"TRACE_NR_OP_MODE": "invalid"}, {"READAHEAD_KB": "-1"},
        ):
            with self.subTest(overrides=overrides):
                result = self.run_matrix(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
