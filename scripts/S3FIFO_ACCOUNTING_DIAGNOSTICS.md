# Direct S3FIFO accounting: admission diagnostics, logging revision 5

Documentation update (2026-10-09): retired SST/window-probe offline tools were
removed. Historical results remain; current aggregation uses
`summarize_s3fifo_repeats.py`. This cleanup does not change accounting counters.

## Revision 5 cleanup

Removed `diag_add_rollback_small/main`: reason counters already provide the
total failed admission count. The loader snapshots each reason once and emits
`add_fail_total` as their sum; no per-small/main failure split is emitted in
revision 5. This saves one atomic increment per failed admission. The actual
small/main counter rollback is UNCHANGED. pre_add_node_missing remains and its
duplicate per-event bpf_printk is removed. Negative-update diagnostics and the
successful-admission debit guard remain necessary during lifecycle repair.

Removed the kernel's `cache_ext evict: batches=...` ratelimited printk and its
five private summary counters. Existing per-memcg requested/returned/submitted/
reclaimed/keep/deferred/fallback statistics and control flow are unchanged.
The old dmesg-only invalid/isolate_fail breakdown is no longer emitted; this
was not an interval counter used by the current analysis. Existing per-case
pr_debug messages remain for opt-in kernel debugging.

Migration/admission diagnostics remain. The subsequent October 6 cleanup removed
LevelDB read/compaction instrumentation and the window probes. The 30s ops/cgroup
snapshots and ordinary perf remain. Historical logs are preserved.
See [DIAGNOSTICS_CLEANUP.md](DIAGNOSTICS_CLEANUP.md) for current builds/commands.
Neither cleanup implements migration ownership transfer.

Rebuild the policy/loader with `make -C policies cache_ext_s3fifo.out`. To remove
the kernel printk too, rebuild/install the kernel and reboot. The subsequent
diagnostics cleanup also requires a LevelDB/My-YCSB rebuild. revision=5 identifies the loader schema, not which
kernel is running. Old revision=4 logs can still be read; derive their failure
total from the same four reason fields (or the two old rollback fields).

## Revision 4 diagnostics (retained unless noted above)

Revision 4 adds failure classification without changing admission, eviction,
rollback or migration behavior. Rebuild/install the kernel and reboot, then
rebuild Direct S3FIFO with `make -C policies cache_ext_s3fifo.out` (the local
policy build has also been checked). No LevelDB/My-YCSB rebuild is needed.
Do not interpret a revision=4 loader line as proof the new kernel is running.

Kernel list_add/list_add_tail now return distinct errno values. The existing
30s `[S3FIFO accounting]` line adds:

| Field | Kernel outcome |
|---|---|
| add_fail_list_missing | -ENOENT: target list not found in folio's registry |
| add_fail_node_invalid | -ESTALE: no valid node at the locked lookup |
| add_fail_already_linked | -EEXIST: node's policy link is not empty |
| add_fail_other | Other failure, including old kernel's undifferentiated -1 |

Their sum equals add_rollback_small + add_rollback_main at quiescence; concurrent
relaxed snapshots may briefly differ. pre_add_node_missing remains separate.
No per-event printk or success/accessed-path diagnostic counter is added.
Each failed admission adds one atomic reason-counter increment.

The existing `memory.cache_ext_reclaim_stat` also exposes
`migration_success_node_present_folios`: successful common
`move_to_new_folio()` operations with a non-NULL source cache_ext_node, counted
against the source memcg if cache_ext_valid. This is a folio/event count, not
bytes, base pages, unique folios or reclaimed pages. It does NOT validate node
ownership, distinguish stale pointers, or cover every replacement path (e.g.
FUSE replace_page_cache_folio). The source is still alive/locked; the diagnostic
never dereferences the node or changes its pointer/list/state. It adds one
atomic increment per matching migration, plus a pointer check on successful
migration. This is not on folio_accessed or policy scoring paths.
Storage is one atomic64 per memcg, not a new field in every node. It is kept
outside the reclaim batch array to avoid enlarging reclaim stack frames or
adding work to their publication loops.

Existing cgroup collectors save the new field verbatim in memory logs and
LevelDB JSONL. The generic io_windows parser produces the 30s delta column
`reclaim_migration_success_node_present_folios`. Its `reclaim_` prefix denotes
the source stats file, not a reclaim outcome. Missing on old kernels is NOT
zero. When memory_poll=auto suppresses the standalone poller, use the aligned
JSONL/CSV. No new probes, threads or polling intervals are needed.

Nonzero migration counts plus already-linked failures support the migration
hypothesis, but do not alone prove both events concern the same folio. This
step diagnoses the lifecycle gap; it deliberately does not repair it.

## Previous revisions

Revision 3 keeps revision 2's accounting behavior, but removes the two
unadmitted-debit diagnostic counters and the per-failure list-add bpf_printk.
The successful-admission marker, debit guard and atomic rollback remain.
Insertion failures are still counted by small/main; detailed failure-reason
classification is not implemented by this cleanup.

Revision 2 blocks deletion debits for nodes that were never admitted, rolls
back the current increment when list insertion fails, and removes ordinary
negative-counter reset assignments. Ghost behavior and eviction scores are
unchanged. These are targeted fixes, not a transactional redesign of accounting.

The Direct S3FIFO loader emits `[S3FIFO accounting]` at startup, every 30 seconds,
and on SIGINT/SIGTERM. `mono_ns` uses CLOCK_MONOTONIC, matching the existing
LevelDB IO-window timestamps; `unix_ns` is wall time. Startup includes the
pre-benchmark/warmup interval: use timestamp alignment and cumulative deltas,
not a final total divided only by Trace operations.

The benchmark spools policy stdout/stderr to temporary regular files outside
the workload cgroup, then emits them into the existing console.log at policy
shutdown. This prevents a full unread PIPE from blocking the loader or hiding
its final counters. It does not promise crash-persistent logs or live console
updates. No extra reader thread is introduced.

| Field | Meaning |
|---|---|
| marker_mask | Kernel successful-admission state bit; currently 16 |
| small / main | Existing signed policy counters, not measured list lengths |
| revision | 4 adds admission-reason/migration diagnostics; 3 reduced instrumentation; 2 has extra logging/counters |
| add_rollback_small / add_rollback_main | Failed list insertion followed by atomic rollback of this admission's increment |
| pre_add_node_missing | Node lookup failed before either counter increment or list insertion |
| small_negative_updates / main_negative_updates | Delete/transfer/rollback atomic update left a negative result, computed from that atomic's returned old value; includes updates of an already negative count, not just crossings |

Anomaly counters are cumulative folio/event counts, not bytes/base pages. They
are not necessarily unique-node counts. A blocked debit no longer changes size.
Snapshots of different fields are independent, not an atomic transaction.
Admission increments themselves are not included in negative-update counters.
An add-rollback count records an increment that has been undone, unlike the old
add-failure count. Do not compare these as outstanding size errors. Zero
anomalies do not prove all accounting is
correct: this does not measure every migration race, actual list length or
policy-switch ownership.

## Reliable admission evidence

The kernel sets `CACHE_EXT_NODE_EVER_ADMITTED` in existing `node->state` only
after successful list insertion, under the registry write lock. No new node
field is added. The bit remains for the node lifetime; it is not current
membership and does not identify small/main or a particular policy generation.
Use this diagnostic for a fresh Direct S3FIFO attachment without hot policy
switching, as in the current benchmark. Deletion reads the live node before
valid_folios_del; it does not inspect list pointers without locking.

A new init-only kfunc returns the mask and provides an old-kernel load-time
dependency. The new policy will fail to load on the old kernel rather than
falsely count every deletion as unadmitted. Existing policies need not call it.
Raw node_state in window-probe output now includes bit 16 for admitted nodes;
that bit does NOT mean deferred/removed/freed. Existing observers retain the
raw state and do not filter it by equality to zero.

## Behavior and overhead

No changes to ghost lookup/insertion, victim scores, accessed callbacks, or
the small/main selection formula. Corrected counts can change which queue that
formula selects. Node lookup now precedes admission, but metadata initialization
still follows successful list insertion; failed duplicate admission must not
overwrite the existing node's metadata or historical admission bit.
Small/main migration still uses separate atomic updates after list movement,
so counter snapshots may transiently disagree with physical membership. This
patch does not claim to fix every migration race or support hot policy switching.
No queue walks or per-page diagnostic hash map. One atomic OR per successful
list admission; deletion adds a state-bit check; anomaly branches update
counters; transfer diagnostics reuse existing atomic results. Userspace reads
the existing BSS mapping every 30 seconds. Overhead is limited but not zero,
particularly if anomaly counters fire frequently. Baseline has no S3FIFO
accounting output. Dispatcher S3FIFO counters were not added in this step.

## Revision 3 build and run (historical; commands below are retired)

Do not pass the old diagnostic arguments below to current scripts.

Revision 3 only requires rebuilding Direct S3FIFO's BPF object and loader:
`make -C policies cache_ext_s3fifo.out`. The earlier admission-tracking kernel
must already be running (the latest diagnostic experiments used marker_mask=16).
If it is, this revision needs no kernel rebuild or reboot. No LevelDB
or My-YCSB rebuild is needed. `runtime=1200` and the restored perf/no_perf batch
behavior are unchanged. Look for `[S3FIFO accounting] revision=3`.

For low-interference repeats, omit the old explicit offcpu/refill options:

```sh
./a_total_single_policy_compare.sh perf_mode=record sst_sample_every=0 diagnostic_ops=130000000:140000000,150000000:160000000 diagnostic_offcpu=false diagnostic_refill_every=0 results_dir=/root/cache_ext/results/accounting_rev3
```

The main Twitter batch defaults to record-only for the perf round, not the
whole-run page-cache perf-stat monitor. The no_perf round uses none. Without
diagnostic_ops, existing startup perf recording is used rather than short
operation-progress windows. The command above retains the previous progress
windows while disabling BPF window probes. Probe code is retained for opt-in.

With LevelDB diagnostics enabled, `memory_poll=auto` skips the independent 5s
cgroup poller: cgroup data and exact operation deltas remain in 30s snapshots
and phase boundaries in leveldb_io JSONL / io_windows CSV. The mem log contains
a disabled marker to prevent stale samples from being mistaken for this run.
Use `memory_poll=true` (and test_memory=true) to restore separate sampling;
without LevelDB diagnostics, auto preserves the old independent poller.
Twitter result JSON records memory_poll and memory_poll_enabled.

Offline tests compile the actual policy callbacks with host stubs, covering
balanced admission/removal, blocked debits, failed and duplicate admission,
missing nodes, migration arithmetic without clamping, and loader output
spooling. They do not exercise the kernel BPF verifier or concurrent callbacks.
