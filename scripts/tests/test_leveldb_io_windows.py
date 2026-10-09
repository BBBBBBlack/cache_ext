import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("io_windows", ROOT / "scripts/leveldb_io_windows.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def snap(boundary, ns, ops, io="8:0 rbytes=0 wbytes=0 rios=0 wios=0\n"):
    return dict(event="snapshot", stage="Trace", boundary=boundary, mono_ns=ns,
                wall_ns=ns, snapshot_end_mono_ns=ns+1000, ops={"READ": ops},
                reads={"get": {"read_calls": ops, "returned_bytes": ops*100}},
                cgroup={"io.stat": io, "memory.stat": "pgscan 123\nfile_dirty 4096\n",
                        "memory.current": "8192\n", "memory.pressure": "full total=0\n",
                        "cache_ext_reclaim.stat": None})


class WindowsTest(unittest.TestCase):
    def test_cpu_time_deltas_per_op_and_missing_reset_zero_ops(self):
        a, b = snap('begin', 1, 0), snap('end', 30_000_000_001, 10)
        a['cgroup']['cpu.stat'] = 'usage_usec 100\nuser_usec 60\nsystem_usec 40\n'
        b['cgroup']['cpu.stat'] = 'usage_usec 400\nuser_usec 260\nsystem_usec 140\n'
        row = list(mod.windows([a, b]))[0]
        for key, value in [('usage', 300), ('user', 200), ('system', 100)]:
            self.assertEqual(row[f'cpu_{key}_usec'], value)
            self.assertEqual(row[f'cpu_{key}_usec_per_op'], value / 10)
        b['ops']['READ'] = 0
        row = list(mod.windows([a, b]))[0]
        self.assertEqual(row['cpu_usage_usec'], 300)
        self.assertIsNone(row['cpu_usage_usec_per_op'])
        b['ops']['READ'] = 10
        for unavailable in (None, 'usage_usec 99\nuser_usec 59\nsystem_usec 39\n'):
            b['cgroup']['cpu.stat'] = unavailable
            row = list(mod.windows([a, b]))[0]
            self.assertIsNone(row['cpu_usage_usec'])
            self.assertIsNone(row['cpu_usage_usec_per_op'])
        del a['cgroup']['cpu.stat']
        del b['cgroup']['cpu.stat']
        self.assertIsNone(list(mod.windows([a, b]))[0]['cpu_usage_usec_per_op'])

    def test_migration_counter_is_preserved_as_interval_delta(self):
        key = 'migration_success_node_present_folios'
        a, b = snap('begin', 1, 0), snap('end', 30_000_000_001, 10)
        a['cgroup']['cache_ext_reclaim.stat'] = f'{key} 7\n'
        b['cgroup']['cache_ext_reclaim.stat'] = f'{key} 19\n'
        self.assertEqual(list(mod.windows([a,b]))[0]['reclaim_'+key], 12)
        a['cgroup']['cache_ext_reclaim.stat'] = None
        self.assertIsNone(list(mod.windows([a,b]))[0]['reclaim_'+key])

    def test_incomplete_stage_is_marked(self):
        a, b = snap("begin", 1, 0), snap("periodic", 30_000_000_001, 100)
        self.assertFalse(list(mod.windows([a, b]))[0]["stage_complete"])

    def test_denominator_devices_missing_and_partial(self):
        a = snap("begin", 1, 0, "8:0 rbytes=10 wbytes=0 rios=1 wios=0\n253:0 rbytes=10 wbytes=0 rios=1 wios=0\n")
        b = snap("end", 15_000_000_001, 10, "8:0 rbytes=110 wbytes=0 rios=3 wios=0\n253:0 rbytes=110 wbytes=0 rios=3 wios=0\n")
        rows = list(mod.windows([a, b]))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["read_bytes_per_op"], 10)
        self.assertEqual(rows[0]["read_ios_per_kop"], 200)
        self.assertAlmostEqual(rows[0]["throughput_ops_s"], 10/15)
        self.assertNotIn("reclaim_requested_pages", rows[0])
        a["cgroup"]["io.stat"] = None
        rows = list(mod.windows([a, b]))
        self.assertIsNone(rows[0]["read_bytes_per_op"])
        self.assertEqual(rows[0]["io_status"], "missing_device_endpoint")

    def test_counter_reset_and_compaction_overlap(self):
        a, b = snap("begin", 1, 0), snap("end", 30_000_000_001, 10)
        a["cgroup"]["io.stat"] = "8:0 rbytes=100 wbytes=0 rios=2 wios=0\n"
        events = [a, dict(event="compaction_begin", id=1, mono_ns=10_000_000_001),
                  b, dict(event="compaction_end", id=1, mono_ns=40_000_000_001)]
        row = list(mod.windows(events))[0]
        self.assertIsNone(row["read_bytes_per_op"])
        self.assertEqual(row["compaction_overlap_seconds"], 20)
        self.assertEqual(row["io_status"], "missing_or_reset_counter")
        a["ops"]["READ"] = 11
        with self.assertRaises(ValueError):
            list(mod.windows(events))

    def test_cpp_snapshots_without_read_path_instrumentation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            binary, log = tmp / "probe", tmp / "io.jsonl"
            (tmp / "memory.cache_ext_reclaim_stat").write_text("keep_dirty_pages 123\n")
            cpu = 'usage_usec 1200\nuser_usec 900\nsystem_usec 300\n'
            (tmp / 'cpu.stat').write_text(cpu)
            subprocess.run(["g++", "-std=c++17", "-O2", "-pthread", "-I", str(ROOT/"My-YCSB/leveldb"),
                            str(ROOT/"scripts/tests/leveldb_io_probe.cc"),
                            str(ROOT/"My-YCSB/leveldb/benchmark_snapshots.cpp"), "-o", str(binary)], check=True)
            subprocess.run([str(binary), str(log), str(tmp)], check=True)
            events = mod.load_events(log)
            rows = list(mod.windows(events))
            self.assertEqual(events[0]["version"], 2)
            self.assertTrue(all(e["event"] in ("schema", "snapshot") for e in events))
            self.assertTrue(all("reads" not in e for e in events))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["completed_ops"], 6)
            self.assertNotIn("compaction_overlap_seconds", row)
            self.assertEqual(events[-1]["cumulative_ops"], 7)
            self.assertEqual(row["reclaim_keep_dirty_pages"], 0)
            self.assertEqual(events[-1]['cgroup']['cpu.stat'], cpu)
            self.assertEqual(row['cpu_usage_usec'], 0)
            self.assertEqual(row['cpu_usage_usec_per_op'], 0)
            # Missing cpu.stat is null, not a fabricated zero.
            (tmp / 'cpu.stat').unlink()
            missing_log = tmp / 'missing_cpu.jsonl'
            subprocess.run([str(binary), str(missing_log), str(tmp)], check=True)
            missing_events = mod.load_events(missing_log)
            self.assertIsNone(missing_events[-1]['cgroup']['cpu.stat'])
            self.assertIsNone(list(mod.windows(missing_events))[0]['cpu_usage_usec_per_op'])
            self.assertIsNone(row["read_bytes_per_op"])
            self.assertEqual(len(list(mod.windows(events, True))), 2)
            self.assertEqual(sum(e.get("boundary") == "end" for e in events), 2)

    def test_shell_wrapper_output_names_and_failure_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            fixture = [dict(event="schema", version=1), snap("begin", 1, 0),
                       snap("end", 30_000_000_001, 100)]
            fixture_path = tmp/"fixture.jsonl"
            fixture_path.write_text("".join(json.dumps(e)+"\n" for e in fixture))
            stub = tmp/"bench.py"
            stub.write_text("import os, pathlib, sys\n"
                            "path = sys.argv[sys.argv.index('--leveldb-io-log')+1]\n"
                            "pathlib.Path(path).write_text(pathlib.Path(os.environ['FIXTURE']).read_text())\n"
                            "sys.exit(int(os.environ.get('FAIL', '0')))\n")
            env = dict(os.environ, BASE_DIR=str(ROOT), STUB=str(stub), FIXTURE=str(fixture_path),
                       PREFIX=str(tmp/"output with spaces"))
            command = 'set -eu -o pipefail\nsource "$BASE_DIR/eval/leveldb_io_monitor.sh"\n' \
                      'BASE_CMD=(python3 "$STUB")\nrun_with_leveldb_io baseline "$PREFIX" none\n'
            for status in (0, 7):
                result = subprocess.run(["bash", "-c", command], env=dict(env, FAIL=str(status)),
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, status, result.stdout+result.stderr)
            for suffix in ("_leveldb_io_none_baseline.jsonl", "_leveldb_io_none_baseline.jsonl.previous",
                           "_io_windows_none_baseline.csv", "_throughput_none_baseline.log"):
                self.assertTrue(Path(env["PREFIX"]+suffix).is_file())


if __name__ == "__main__":
    unittest.main()
