#!/usr/bin/env python3
"""~55-second real LevelDB smoke test, tiny temporary DB, no sudo/cgroup/perf."""
import csv
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("io_windows", ROOT / "scripts/leveldb_io_windows.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def main():
    with tempfile.TemporaryDirectory(prefix="leveldb-io-smoke-") as temp:
        temp = Path(temp)
        config = {
            "database": {"key_size": 24, "value_size": 128, "nr_entry": 10000},
            "workload": {"nr_warmup_op": 100, "warmup_runtime_seconds": 0,
                         "runtime_seconds": 0, "nr_op": 120000, "nr_thread": 2,
                         "next_op_interval_ns": 300000,
                         "operation_proportion": {"read": .5, "update": .5, "insert": 0,
                                                  "scan": 0, "read_modify_write": 0},
                         "request_distribution": "uniform", "zipfian_constant": .99,
                         "scan_length": 10},
            "leveldb": {"data_dir": str(temp/"db"), "cache_size": 0,
                        "write_buffer_size": 65536, "max_file_size": 1048576, "print_stats": True},
        }
        path, log = temp/"config.yaml", temp/"reads.jsonl"
        path.write_text(yaml.safe_dump(config))
        with (temp/"console.log").open("w") as console:
            for binary, args in (
                ("init_leveldb", []),
                ("run_leveldb", ["--io-log", str(log), "--io-cgroup", str(temp/"no-cgroup")]),
            ):
                result = subprocess.run([str(ROOT/"My-YCSB/build"/binary), str(path), *args],
                                        stdout=console, stderr=subprocess.STDOUT, timeout=90)
                if result.returncode:
                    raise RuntimeError((temp/"console.log").read_text())
        events = mod.load_events(log)
        assert events[0]["version"] == 2
        assert all(e["event"] in ("schema", "snapshot") for e in events)
        assert all("reads" not in e for e in events)
        rows = list(mod.windows(events))
        assert len(rows) >= 2, rows
        assert any(r["boundary"] == "periodic" for r in rows)
        # With no runtime limit, every worker must finish its finite workload.
        # Still derive window denominators from actual completed operations.
        completed = sum(r["completed_ops"] for r in rows)
        final = [e for e in events if e.get("event") == "snapshot"
                 and e.get("stage") == "Uniform" and e.get("boundary") == "end"][-1]
        assert completed == sum(final["ops"].values())
        assert completed == 240000, completed
        warmup = [e for e in events if e.get("event") == "snapshot"
                  and e.get("stage") == "Uniform (Warm-Up)"
                  and e.get("boundary") == "end"][-1]
        assert sum(warmup["ops"].values()) == 200, warmup["ops"]
        assert any(e.get("stage", "").endswith("(Warm-Up)") for e in events)
        subprocess.run(["python3", str(ROOT/"scripts/leveldb_io_windows.py"), str(log),
                        "--throughput-log", str(temp/"throughput.log")], check=True)
        with log.with_suffix(".csv").open() as stream:
            assert len(list(csv.DictReader(stream))) == len(rows)
        print(json.dumps({"windows": len(rows), "ops": completed}, indent=2))


if __name__ == "__main__":
    main()
