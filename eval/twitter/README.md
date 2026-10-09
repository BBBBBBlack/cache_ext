# Twitter traces benchmark

This script benchmarks Twitter traces performance with LevelDB using 5 different
policies:

- Baseline
- Baseline MGLRU
- cache_ext LHD
- cache_ext S3-FIFO
- cache_ext LFU

It corresponds to Figure 7 in the paper.

Outputs, where CLUSTER is one of (17 18 24 34 52):

- `results/twitter_traces_${CLUSTER}_results.json` (for baseline and cache_ext)
- `results/twitter_traces_${CLUSTER}_results_mglru.json` (for MGLRU)

## Single-policy monitoring comparison

`a_single_policy_compare.sh` accepts `perf_mode=none|record|tracepoint|both`:

| Mode | perf record, 60 seconds | Page-cache tracepoint counting, runtime seconds |
| --- | --- | --- |
| `none` | Off | Off |
| `record` | On | Off |
| `tracepoint` | Off | On |
| `both` | On | On |

The legacy `test_perf=true/false` options map to `both/none`. An explicit
`perf_mode` takes precedence regardless of argument order. `test_memory`
remains independent, as do the readahead settings. Thus `none` means no perf
instrumentation; also set `test_memory=false` to disable the memory/throughput
log monitor. **Perf** monitor
timing is unchanged: discovery of run_leveldb followed by a fixed warmup delay,
not synchronization to the actual measurement start. The benchmark snapshots
below instead use actual workload-stage boundaries.

```bash
./eval/twitter/a_single_policy_compare.sh 34 s3fifo 3G \
    perf_mode=record test_memory=true runtime=3600 warmup=45
```

JSON and monitoring filenames include the mode. For example, the result is
`twitter_spc_s3fifo_cluster34_3G_record.json`. The unsuffixed JSON remains a
copy of the latest successful run for existing callers. Result configs record
the selected mode and memory-monitor settings. `results_dir=<path>` changes
the output directory for the JSON and all monitor logs.

`a_total_single_policy_compare2.sh` runs baseline and the selected policy for
every mode, keeping other arguments the same. Edit `CLUSTERS` and `POLICIES`
near its start; the defaults are cluster34 and S3FIFO. Environment variables
control the experiment:

```bash
PERF_MODES="none record tracepoint both" REPETITIONS=2 \
    CGROUP_SIZE=3G RUNTIME=3600 WARMUP=45 \
    TEST_MEMORY=true MEMORY_INTERVAL=5 READAHEAD_KB=128 \
    ./eval/twitter/a_total_single_policy_compare2.sh
```

`PERF_MODES` controls the order and can select a subset, such as
`PERF_MODES="none tracepoint"`. Defaults are one repetition, 3G, 3600-second
runtime, 45-second warmup, memory sampling enabled every five seconds, and
`READAHEAD_KB=default` (leave the device setting unchanged). Set an explicit
KB value to hold readahead fixed; `0` disables device readahead. The default
`TRACE_NR_OP_MODE=ignore-nr-op` retains time-limited execution. A different
mode does not guarantee an identical trace-operation range at fixed runtime.

Results are saved directly under `results/`, with subdirectories
`cluster34/s3fifo/repeat1/none`, `record`, `tracepoint` and `both`. There is no
timestamped batch directory. Each mode directory contains the exact command,
complete console log, JSON and enabled monitoring logs. `REPETITIONS` defaults
to `1`; larger values add `repeat2`, `repeat3`, and so on.
`RESULTS_DIR` can override the output root. Existing mode/repetition
directories are rejected to prevent overwriting. Any benchmark failure stops
the remaining matrix. Run this matrix without concurrent fio/YCSB/kernel
builds; it does not lock other benchmark entry points or isolate their global
cache drops.

Offline verification (does not invoke perf, workloads or kernel setup):

```bash
python3 eval/twitter/test_monitor_modes.py
```

## Benchmark snapshots (Twitter and YCSB)

`test_memory=true` enables begin / approximately 30-second / end snapshots
of completed operations and the selected cgroup's `io.stat`, `memory.stat`,
`memory.pressure`, `memory.current`, and `memory.cache_ext_reclaim_stat`.
Existing worker counters are reused: no extra per-op or per-read updates.
The writer lives in `My-YCSB/leveldb/benchmark_snapshots.cpp`, not LevelDB.
Periodic and end snapshots are serialized; workers are not paused.

Removed: `test_leveldb_io`, `sst_sample_every`, all `diagnostic_*` switches,
read-source attribution, per-SST timing/counters, extra compaction event logging,
and short-window BPF observers. Removed switches fail explicitly even when
false/zero. Ordinary `test_perf` / `perf_mode` monitoring is unchanged.
This removes added instrumentation, not real compaction, native LevelDB
LOG/stats or native read sampling used to schedule compaction.

Build userspace from the repository root:

```bash
cmake -S My-YCSB -B My-YCSB/build -DCMAKE_BUILD_TYPE=Release
cmake --build My-YCSB/build --target run_leveldb init_leveldb -j4
My-YCSB/build/run_leveldb --diagnostics-version
```

The capability output must be `benchmark-snapshots-v1`. An old instrumented
binary is rejected when snapshots are requested. My-YCSB links in-tree LevelDB.

Filenames remain compatible; contents now use JSONL schema version 2:

- `*_leveldb_io_<mode>_<stage>.jsonl`: completed-op and cgroup snapshots only.
- `*_io_windows_<mode>_<stage>.csv`: deltas, throughput and per-op IO.
- `*_throughput_<mode>_<stage>.log`: the same measured windows.

No read-source/compaction fields are emitted (missing is NOT zero). The offline
parser still accepts historical schema 1 logs. JSONL is rotated to `.previous`;
use a fresh results directory for every comparison.

`memory_poll=auto` adds no duplicate 5-second poller. Set
`memory_poll=true test_memory=true` for additional independent sampling.
The mem log has a disabled marker when that poller is off.

Intervals use measured monotonic time and completed-op differences, not rounded
throughput multiplied by assumed duration. Boundaries include a small collection/
gate/join margin. IO completion may cross boundaries. Final partial windows are
retained; incomplete stages have `stage_complete=false`. CSV has one row per
window per device: never sum stacked dm/physical device counters or duplicate
operation counts. Missing/reset counters stay blank. PSI uses total-time deltas.
Snapshots still have nonzero cost; `test_memory=false` is the control.

Removing custom kernel tracepoints requires rebuilding/installing the kernel
and rebooting. See [diagnostics cleanup](../../scripts/DIAGNOSTICS_CLEANUP.md).

### Operation-count boundaries

All workers rendezvous once at stage start. No operation executes before the
coordinator's begin snapshot and common measurement start time. Every returned
`do_operation()` counts once and contributes one latency sample, even if a stop
request arrives while it is in flight. This is a completed-attempt count, not a
new success/error classification of database requests.

A worker reaching its finite operation limit/EOF no longer stops its peers.
Runtime expiry stops fetching new operations; already fetched operations finish
(including ones being decoded/paced) so trace entries are not silently lost. The
last worker records the end time, so overall throughput includes their drain
time. The existing monitor still checks runtime on its 10-second cadence (it is
not a hard per-operation deadline). Each warmup/benchmark stage has a new
measurement object and separate counters. Startup synchronization adds no lock
to the per-operation statistics path.

`op_count_arr` is also the latency denominator. Realtime throughput uses the
monitor's previous cumulative count instead of a second per-op increment/reset.
Both `latency_count_arr` and `rt_op_count_arr` were removed, saving two atomic
updates per completed operation. Historical results from the old early-stop /
dropped-boundary-op behavior are not strictly equivalent; rerun baseline and
policies with the same new binary for comparisons.

The unused LevelDB `key_fails` and empty `reset_stats()` were removed. Printed
LevelDB compaction statistics remain cumulative since DB open (including
warmup); use stage-aligned diagnostic deltas to exclude warmup. FIFO still prints
`cb_continue`, computed from its three skip counters rather than maintained
separately. The disabled LFU debug stats map/keys/updates were removed without
changing LFU scoring or list behavior.

### Statistics audit

Removed the duplicate embedded Twitter/YCSB `append_validation_summary` code:
its IO window could include warmup, denominator was throughput × configured
runtime, result selection was positional, and add-minus-prefetch was labeled
`demand_miss_estimate`. New outputs do not generate that estimate or pretend the
PID-attached perf window matches the full benchmark. Historical logs/scripts
are not deleted or rewritten.

Retained the raw perf/tracepoint logs, memory/PSI/IO logs, latency/throughput,
requested/returned/submitted/reclaimed/fallback and keep/deferred reason counters:
they answer different questions. In particular, `pgscan` does **not** measure all
cache_ext policy scanning, and dirty keeps count attempts, not unique pages.
No kernel or policy counters were removed in this userspace-only change.

Offline regeneration/tests:

```bash
python3 scripts/leveldb_io_windows.py path/to/leveldb_io.jsonl
python3 -m unittest discover -s scripts/tests -p 'test_leveldb_io_windows.py' -v
python3 scripts/tests/smoke_leveldb_io.py  # small temporary DB, ~55 seconds
```
