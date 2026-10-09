# Diagnostics cleanup — updated 2026-10-09

Removed from live code:

- LevelDB read/pread/mmap counters and GET/UPDATE/compaction source attribution.
- Per-SST timing, TLS hash tables, counters and histograms.
- Extra compaction start/end JSON events and input/output SST formatting.
- Progress-triggered perf/offcpu/refill observer and scripts/window_probe sources,
  loader, maps and generated binaries.
- Custom kernel events cache_ext_queue_state, cache_ext_victim, filemap_read_wait,
  including their emitters in filemap and cache_ext list helpers.

Ordinary filemap add/delete/prefetch events remain. This does not disable actual
compaction, native LevelDB LOG/stats, native read sampling, reclamation/deferred
behavior, or admission accounting guards.

Retained:

- Exact operation counts, latency/throughput and measurement boundaries.
- Begin/30s/end ops and cgroup snapshots controlled by test_memory, implemented
  in My-YCSB/leveldb/benchmark_snapshots.cpp, without added read-path counters.
- Standard test_perf / perf_mode recording and page-cache event counting.
- requested/returned/submitted/reclaimed/keep/deferred/fallback counters.
- S3FIFO failure reasons, missing-node/negative-update checks and migration
  counter: the underlying lifecycle issue has not been repaired yet.
- Historical result logs. On October 9, retired v2/SST/window-probe analysis
  scripts and their dedicated compatibility test/documentation were removed.
  This did not delete result logs or change runtime collectors.
- Current offline tools: `leveldb_io_windows.py` (snapshot conversion) and
  `summarize_s3fifo_repeats.py` (repeat summaries).

Removed CLI options now fail explicitly, even with false/0 values:
test_leveldb_io, sst_sample_every, diagnostic_*. Snapshots follow test_memory.
Existing *_leveldb_io_*.jsonl filenames remain, but schema 2 contains only ops
and cgroup snapshots. Absent read/compaction fields mean not measured, NOT zero.

CPU addition: snapshots also read the selected benchmark cgroup's `cpu.stat`
at begin/30s/end (baseline and policy, perf and no_perf when test_memory=true).
The raw text is stored as `cgroup["cpu.stat"]` in the existing JSONL. Window CSVs
contain `cpu_usage_usec`, `cpu_user_usec`, `cpu_system_usec` (window deltas), and
the corresponding `*_per_op` columns (microseconds per completed operation).
Old logs/missing files/reset counters stay blank; zero-op windows have no per-op
value. These are cgroup-wide CPU times, not host utilization or request latency.
No per-op CPU instrumentation is added. CPU fields repeat on each device row;
do not sum them across devices. For a full stage use total CPU delta / total ops,
not an unweighted average of the per-window ratios. Rebuild run_leveldb to enable;
this CPU-only addition does not require a kernel rebuild or reboot.

## Build and run

Rebuild userspace:

```sh
cmake -S My-YCSB -B My-YCSB/build -DCMAKE_BUILD_TYPE=Release
cmake --build My-YCSB/build --target run_leveldb init_leveldb -j4
```

Apply the kernel changes through the project's install_kernel.sh build/install
workflow and reboot. Object compilation alone does not change the running kernel.

From eval/twitter:

```sh
./a_total_single_policy_compare.sh perf_mode=record results_dir=/root/cache_ext/results/diagnostics_cleanup
```

Cluster/policy selection, sizing, enabled rounds and baseline reuse are set by
the batch script. Its current runtime default is 3600 seconds; check the script
and each result's `command.sh` for effective settings. Ordinary perf recording
uses the normal warmup-delay window, not the retired operation-progress windows.

test_memory=true collects snapshots in both rounds. memory_poll=auto avoids a
duplicate independent poller; memory_poll=true adds it explicitly. With the
single-run script, test_perf=false test_memory=false disables both optional
observers; ordinary benchmark operation/latency measurements still run.
