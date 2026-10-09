#!/bin/bash
set -eu -o pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Set one or more policies here, for example:
# POLICIES=(s3fifo fifo lfu)
POLICIES=(s3fifo)
CLUSTERS=(17 18 20 24 25)

REPETITIONS="${REPETITIONS:-1}"
TEST_MEMORY="${TEST_MEMORY:-true}"
MEMORY_INTERVAL="${MEMORY_INTERVAL:-5}"
CACHE_EXT_CGROUP="${CACHE_EXT_CGROUP:-cache_ext_ctest}"
BASELINE_CGROUP="${BASELINE_CGROUP:-btest}"
RUNTIME="${RUNTIME:-3600}"
WARMUP="${WARMUP:-45}"
TRACE_NR_OP_MODE="${TRACE_NR_OP_MODE:-ignore-nr-op}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/../../results}"
WSS_CSV="${WSS_CSV:-/root/data/twitter/traces/twitter_wss.csv}"
CGROUP_PCT="${CGROUP_PCT:-50}"
MAX_CGROUP_BYTES="${MAX_CGROUP_BYTES:-$((12 * 1024 * 1024 * 1024))}"
LOCAL_TRACES_DIR="${LOCAL_TRACES_DIR:-/root/data/twitter/traces}"
REMOTE_HOST="${REMOTE_HOST:-root@10.26.43.163}"
REMOTE_TRACE_DIR="${REMOTE_TRACE_DIR:-/data/czf_test/cache_ext}"
REMOTE_COMPLETE_TRACE_DIR="${REMOTE_COMPLETE_TRACE_DIR:-/mnt/data/TwitterCacheTrace/czf_test/cache_ext}"
RSYNC_RSH="${RSYNC_RSH:-ssh -p 12138 -o Compression=no -o ControlMaster=auto -o ControlPersist=10m -o ControlPath=/tmp/cache_ext_rsync_%r@%h:%p}"
RSYNC_OPTS=(-a --partial --inplace --whole-file --info=progress2 -s -e "$RSYNC_RSH")

# These command-line options configure diagnostics only; cluster/policy/WSS
# settings above retain their existing defaults. Parse before any trace cleanup.
PERF_RUN_MODE=record
MEMORY_POLL="${MEMORY_POLL:-auto}"
usage() {
    echo "Usage: $0 [perf_mode=record|tracepoint|both] [results_dir=PATH] [memory_poll=auto|true|false]"
    echo "Runs perf and no_perf rounds. perf_mode applies ONLY to perf; no_perf always uses none."
    echo "       [memory_poll=auto|true|false] auto skips duplicate polling when benchmark snapshots are enabled"
}
for arg in "$@"; do
    case "$arg" in
        perf_mode=*) PERF_RUN_MODE="${arg#*=}" ;;
        test_leveldb_io=*|sst_sample_every=*|diagnostic_*=*)
            echo "[Error] Retired diagnostics option: $arg; cgroup snapshots now follow TEST_MEMORY" >&2; exit 2 ;;
        memory_poll=*) MEMORY_POLL="${arg#*=}" ;;
        results_dir=*)
            RESULTS_DIR="${arg#*=}"
            if [ -z "$RESULTS_DIR" ]; then
                echo "[Error] results_dir must not be empty" >&2
                exit 2
            fi
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[Error] Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
    esac
done
case "$PERF_RUN_MODE" in
    record|tracepoint|both) ;;
    *) echo "[Error] perf_mode must be record, tracepoint or both; no_perf already uses none" >&2; exit 2 ;;
esac
case "$MEMORY_POLL" in auto|true|false) ;; *) echo "[Error] memory_poll must be auto, true or false" >&2; exit 2 ;; esac
if ! [[ "$REPETITIONS" =~ ^[1-9][0-9]*$ ]]; then
    echo "[Error] REPETITIONS must be a positive integer" >&2
    exit 1
fi
case "$TEST_MEMORY" in
    true|false) ;;
    *) echo "[Error] TEST_MEMORY must be true or false" >&2; exit 1 ;;
esac
for value in "$RUNTIME" "$MEMORY_INTERVAL"; do
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        echo "[Error] RUNTIME and MEMORY_INTERVAL must be positive integers" >&2
        exit 1
    fi
done
if ! [[ "$WARMUP" =~ ^[0-9]+$ ]]; then
    echo "[Error] WARMUP must be a nonnegative integer" >&2
    exit 1
fi
case "$TRACE_NR_OP_MODE" in
    ignore-nr-op|limit-nr-op) ;;
    *) echo "[Error] Invalid TRACE_NR_OP_MODE: $TRACE_NR_OP_MODE" >&2; exit 1 ;;
esac

RESULTS_DIR=$(realpath -m -- "$RESULTS_DIR")
echo "[Info] test_perf modes: true false; repetitions: $REPETITIONS"
echo "[Info] Effective perf modes: perf=$PERF_RUN_MODE no_perf=none"
echo "[Info] Results: $RESULTS_DIR"

resolve_cgroup_size() {
    local cluster="$1"
    python3 - "$WSS_CSV" "$cluster" "$CGROUP_PCT" "$MAX_CGROUP_BYTES" <<'PY'
import csv
import math
import sys

path, cluster, pct_s, max_s = sys.argv[1:]
pct = float(pct_s)
max_bytes = int(max_s)
mib = 1024 * 1024

with open(path, newline="") as f:
    for row in csv.DictReader(f):
        if row.get("cluster") == str(cluster):
            leveldb_kv_bytes = int(row["leveldb_kv_bytes"])
            requested_bytes = math.ceil(leveldb_kv_bytes * pct / 100.0)
            cgroup_mib = math.ceil(requested_bytes / mib)
            cgroup_bytes = cgroup_mib * mib
            cgroup_size = f"{cgroup_mib}M"
            if cgroup_bytes > max_bytes:
                print(f"SKIP {leveldb_kv_bytes} {cgroup_bytes} {cgroup_size}")
            else:
                print(f"RUN {leveldb_kv_bytes} {cgroup_bytes} {cgroup_size}")
            sys.exit(0)

print(f"[Error] Missing cluster={cluster} in {path}", file=sys.stderr)
sys.exit(2)
PY
}

cleanup_cluster_traces() {
    local cluster="$1"
    if [ -z "$cluster" ]; then
        return 0
    fi

    echo "[Cleanup] Removing local trace files for previous cluster=$cluster"
    rm -f \
        "$LOCAL_TRACES_DIR/cluster${cluster}_init.txt" \
        "$LOCAL_TRACES_DIR/cluster${cluster}_bench.txt" \
        "$LOCAL_TRACES_DIR/cluster${cluster}_init_complete.txt" \
        "$LOCAL_TRACES_DIR/.cluster${cluster}_bench.rsync_complete"
}

cleanup_other_cluster_traces() {
    local keep_cluster="$1"
    mkdir -p "$LOCAL_TRACES_DIR"
    find "$LOCAL_TRACES_DIR" -maxdepth 1 -type f \
        \( -name 'cluster*_init.txt' -o \
           -name 'cluster*_bench.txt' -o \
           -name 'cluster*_init_complete.txt' -o \
           -name '.cluster*_bench.rsync_complete' \) \
        ! -name "cluster${keep_cluster}_init.txt" \
        ! -name "cluster${keep_cluster}_bench.txt" \
        ! -name "cluster${keep_cluster}_init_complete.txt" \
        ! -name ".cluster${keep_cluster}_bench.rsync_complete" \
        -delete
}

fetch_cluster_traces() {
    local cluster="$1"
    local init_file="cluster${cluster}_init.txt"
    local bench_file="cluster${cluster}_bench.txt"
    local complete_file="cluster${cluster}_init_complete.txt"
    local db_path="/root/data/leveldb_twitter_cluster${cluster}_db"
    local init_done_marker="$db_path/.twitter_init_complete_with_bench_keys"
    local bench_done_marker="$LOCAL_TRACES_DIR/.cluster${cluster}_bench.rsync_complete"

    mkdir -p "$LOCAL_TRACES_DIR"
    cleanup_other_cluster_traces "$cluster"

    if [ -f "$db_path/CURRENT" ] && [ -f "$init_done_marker" ]; then
        if [ -s "$LOCAL_TRACES_DIR/$bench_file" ] && [ -f "$bench_done_marker" ]; then
            echo "[Fetch] Local DB+marker and completed bench trace exist for cluster=$cluster; skip remote copy"
            return 0
        fi

        echo "[Fetch] Local DB+marker exists for cluster=$cluster; syncing bench trace only"
        rm -f "$bench_done_marker"
        rsync "${RSYNC_OPTS[@]}" "$REMOTE_HOST:$REMOTE_TRACE_DIR/$bench_file" "$LOCAL_TRACES_DIR/"
        if [ ! -s "$LOCAL_TRACES_DIR/$bench_file" ]; then
            echo "[Error] Missing or empty copied bench trace file: $LOCAL_TRACES_DIR/$bench_file" >&2
            return 1
        fi
        touch "$bench_done_marker"
        return 0
    fi

    if [ -s "$LOCAL_TRACES_DIR/$init_file" ] && [ -s "$LOCAL_TRACES_DIR/$bench_file" ] && [ -f "$bench_done_marker" ]; then
        echo "[Fetch] Local init and completed bench trace files already exist for cluster=$cluster; skip remote copy"
        return 0
    fi

    echo "[Fetch] Copying cluster=$cluster trace files from $REMOTE_HOST"
    rsync "${RSYNC_OPTS[@]}" "$REMOTE_HOST:$REMOTE_TRACE_DIR/$init_file" "$LOCAL_TRACES_DIR/"
    rm -f "$bench_done_marker"
    rsync "${RSYNC_OPTS[@]}" "$REMOTE_HOST:$REMOTE_TRACE_DIR/$bench_file" "$LOCAL_TRACES_DIR/"
    touch "$bench_done_marker"
    if ! rsync "${RSYNC_OPTS[@]}" "$REMOTE_HOST:$REMOTE_COMPLETE_TRACE_DIR/$complete_file" "$LOCAL_TRACES_DIR/"; then
        echo "[Warn] Could not copy $complete_file; a_single_policy_compare.sh can regenerate it from init+bench if needed"
    fi

    for f in "$init_file" "$bench_file"; do
        if [ ! -s "$LOCAL_TRACES_DIR/$f" ]; then
            echo "[Error] Missing or empty copied trace file: $LOCAL_TRACES_DIR/$f" >&2
            return 1
        fi
    done
}

declare -A baseline_done
previous_cluster=""

for cluster in "${CLUSTERS[@]}"; do
    cgroup_info="$(resolve_cgroup_size "$cluster")" || exit 1
    read -r cgroup_action leveldb_kv_bytes cgroup_bytes cgroup_size <<< "$cgroup_info"

    if [ "$cgroup_action" = "SKIP" ]; then
        echo "[Skip] cluster=$cluster leveldb_kv_bytes=$leveldb_kv_bytes ${CGROUP_PCT}%_cgroup=$cgroup_size exceeds 12G"
        continue
    fi

    if [ "$cgroup_action" != "RUN" ]; then
        echo "[Error] Unexpected cgroup resolver output for cluster=$cluster: $cgroup_info" >&2
        exit 1
    fi

    cleanup_cluster_traces "$previous_cluster"
    fetch_cluster_traces "$cluster" || exit 1
    previous_cluster="$cluster"

    baseline_done=()

    for policy in "${POLICIES[@]}"; do
        if [ ! -x "$SCRIPT_DIR/../../policies/cache_ext_${policy}.out" ]; then
            echo "[Skip] cluster=$cluster policy=$policy missing executable: policies/cache_ext_${policy}.out"
            continue
        fi

        echo "========================================================"
        echo " Running: cluster=$cluster policy=$policy cgroup=$cgroup_size leveldb_kv_bytes=$leveldb_kv_bytes pct=$CGROUP_PCT% runtime=$RUNTIME"
        echo "========================================================"

        for ((iteration = 1; iteration <= REPETITIONS; iteration++)); do
            run_parent="$RESULTS_DIR/cluster${cluster}/$policy/repeat${iteration}"
            mkdir -p -- "$run_parent"

            # for test_perf in true false; do
            for test_perf in true; do
                if [ "$test_perf" = "true" ]; then
                    mode_label="perf"
                    effective_perf_mode="$PERF_RUN_MODE"
                else
                    mode_label="no_perf"
                    effective_perf_mode=none
                fi

                run_dir="$run_parent/$mode_label"
                if [ -e "$run_dir" ]; then
                    echo "[Warn] Existing result directory will be reused: $run_dir"
                fi
                mkdir -p -- "$run_dir"

                baseline_key="${cluster}_${iteration}_${test_perf}"
                cmd=(
                    "$SCRIPT_DIR/a_single_policy_compare.sh"
                    "$cluster" "$policy" "$cgroup_size"
                    "$TRACE_NR_OP_MODE"
                    "test_perf=$test_perf"
                    "perf_mode=$effective_perf_mode"
                    "test_memory=$TEST_MEMORY"
                    "memory_interval=$MEMORY_INTERVAL"
                    "cache_ext_cgroup=$CACHE_EXT_CGROUP"
                    "baseline_cgroup=$BASELINE_CGROUP"
                    "runtime=$RUNTIME"
                    "warmup=$WARMUP"
                    "results_dir=$run_dir"
                    "memory_poll=$MEMORY_POLL"
                )

                if [ "${baseline_done[$baseline_key]:-false}" = "true" ]; then
                    cmd+=("skip_baseline=true")
                fi

                printf '%q ' "${cmd[@]}" > "$run_dir/command.sh"
                printf '\n' >> "$run_dir/command.sh"
                echo "[Run] iteration=$iteration test_perf=$test_perf perf_mode=$effective_perf_mode results=$run_dir"
                "${cmd[@]}" 2>&1 | tee "$run_dir/console.log"
                baseline_done[$baseline_key]=true
                echo ""
                sleep 5
            done
        done
    done
done

echo "All mapped Twitter trace benchmarks completed: $RESULTS_DIR"
