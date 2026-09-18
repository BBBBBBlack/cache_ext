#!/bin/bash
# set -eu -o pipefail

# SCRIPT_DIR=$(dirname "$(realpath "$0")")

# POLICY="${1:-lfu}"
# CGROUP_SIZE="${2:-}"

# CLUSTERS=(17 18 24 34 52)

# CGROUP_ARG=""
# if [ -n "$CGROUP_SIZE" ]; then
#     CGROUP_ARG="$CGROUP_SIZE"
# fi

# for cluster in "${CLUSTERS[@]}"; do
#     echo "========================================================"
#     echo " Running: cluster=$cluster  policy=$POLICY  cgroup=$CGROUP_SIZE"
#     echo "========================================================"
#     if [ -n "$CGROUP_ARG" ]; then
#         "$SCRIPT_DIR/a_single_policy_compare.sh" "$cluster" "$POLICY" "$CGROUP_ARG"
#     else
#         "$SCRIPT_DIR/a_single_policy_compare.sh" "$cluster" "$POLICY"
#     fi
#     echo ""
#     sleep 5
# done

# echo "All Twitter trace benchmarks completed."

# ./a_single_policy_compare.sh 34 s3fifo 6G test_perf=true test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 s3fifo 6G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 s3fifo 3G test_perf=true test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 s3fifo 3G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 s3fifo 3G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500 disable_readahead=true

# ./a_single_policy_compare.sh 34 lfu 6G test_perf=true test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 lfu 6G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 lfu 3G test_perf=true test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 lfu 3G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 lfu 3G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500 disable_readahead=true


# ./a_single_policy_compare.sh 34 s3fifo 2G test_perf=true test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 s3fifo 2G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 s3fifo 4G test_perf=true test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500
# ./a_single_policy_compare.sh 34 s3fifo 4G test_perf=false test_memory=true cache_ext_cgroup=cache_ext_ctest baseline_cgroup=btest runtime=500

set -u

SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Set one or more policies here, for example:
# POLICIES=(s3fifo lfu arc)
POLICIES=(lru fifo lfu s3fifo lhd)
TEST_PERF="${TEST_PERF:-false}"
TEST_MEMORY="${TEST_MEMORY:-true}"
CACHE_EXT_CGROUP="${CACHE_EXT_CGROUP:-cache_ext_ctest}"
BASELINE_CGROUP="${BASELINE_CGROUP:-btest}"
RUNTIME="${RUNTIME:-4800}"
WSS_CSV="${WSS_CSV:-/root/data/twitter/traces/twitter_wss.csv}"
CGROUP_PCT="${CGROUP_PCT:-70}"
MAX_CGROUP_BYTES="${MAX_CGROUP_BYTES:-$((12 * 1024 * 1024 * 1024))}"
LOCAL_TRACES_DIR="${LOCAL_TRACES_DIR:-/root/data/twitter/traces}"
REMOTE_HOST="${REMOTE_HOST:-root@10.26.43.163}"
REMOTE_TRACE_DIR="${REMOTE_TRACE_DIR:-/data/czf_test/cache_ext}"
REMOTE_COMPLETE_TRACE_DIR="${REMOTE_COMPLETE_TRACE_DIR:-/mnt/data/TwitterCacheTrace/czf_test/trace/cache_ext code}"
RSYNC_RSH="${RSYNC_RSH:-ssh -o Compression=no -o ControlMaster=auto -o ControlPersist=10m -o ControlPath=/tmp/cache_ext_rsync_%r@%h:%p}"
RSYNC_OPTS=(-a --partial --inplace --whole-file --info=progress2 -s -e "$RSYNC_RSH")

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
        "$LOCAL_TRACES_DIR/cluster${cluster}_init_complete.txt"
}

fetch_cluster_traces() {
    local cluster="$1"
    local init_file="cluster${cluster}_init.txt"
    local bench_file="cluster${cluster}_bench.txt"
    local complete_file="cluster${cluster}_init_complete.txt"

    mkdir -p "$LOCAL_TRACES_DIR"

    if [ -s "$LOCAL_TRACES_DIR/$init_file" ] && \
       [ -s "$LOCAL_TRACES_DIR/$bench_file" ] && \
       [ -s "$LOCAL_TRACES_DIR/$complete_file" ]; then
        echo "[Fetch] Local trace files already exist for cluster=$cluster; skip remote copy"
        return 0
    fi

    echo "[Fetch] Copying cluster=$cluster trace files from $REMOTE_HOST"
    rsync "${RSYNC_OPTS[@]}" "$REMOTE_HOST:$REMOTE_TRACE_DIR/$init_file" "$LOCAL_TRACES_DIR/"
    rsync "${RSYNC_OPTS[@]}" "$REMOTE_HOST:$REMOTE_TRACE_DIR/$bench_file" "$LOCAL_TRACES_DIR/"
    rsync "${RSYNC_OPTS[@]}" "$REMOTE_HOST:$REMOTE_COMPLETE_TRACE_DIR/$complete_file" "$LOCAL_TRACES_DIR/"

    for f in "$init_file" "$bench_file" "$complete_file"; do
        if [ ! -s "$LOCAL_TRACES_DIR/$f" ]; then
            echo "[Error] Missing or empty copied trace file: $LOCAL_TRACES_DIR/$f" >&2
            return 1
        fi
    done
}

CLUSTERS=(24 25 26 27 28 29)
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

    baseline_done_nora=false
    baseline_done_default=false

    for policy in "${POLICIES[@]}"; do
        if [ ! -x "$SCRIPT_DIR/../../policies/cache_ext_${policy}.out" ]; then
            echo "[Skip] cluster=$cluster policy=$policy missing executable: policies/cache_ext_${policy}.out"
            continue
        fi

        echo "========================================================"
        echo " Running: cluster=$cluster policy=$policy cgroup=$cgroup_size leveldb_kv_bytes=$leveldb_kv_bytes pct=$CGROUP_PCT%"
        echo "========================================================"

        baseline_args=()
        if [ "$baseline_done_nora" = "true" ]; then
            baseline_args=("skip_baseline=true")
        fi

        "$SCRIPT_DIR/a_single_policy_compare.sh" \
            "$cluster" \
            "$policy" \
            "$cgroup_size" \
            "test_perf=$TEST_PERF" \
            "test_memory=$TEST_MEMORY" \
            "cache_ext_cgroup=$CACHE_EXT_CGROUP" \
            "baseline_cgroup=$BASELINE_CGROUP" \
            "runtime=$RUNTIME" \
            "disable_readahead=true" \
            "${baseline_args[@]}" || exit 1

        baseline_done_nora=true

        echo ""
        sleep 5

        baseline_args=()
        if [ "$baseline_done_default" = "true" ]; then
            baseline_args=("skip_baseline=true")
        fi

        "$SCRIPT_DIR/a_single_policy_compare.sh" \
            "$cluster" \
            "$policy" \
            "$cgroup_size" \
            "test_perf=$TEST_PERF" \
            "test_memory=$TEST_MEMORY" \
            "cache_ext_cgroup=$CACHE_EXT_CGROUP" \
            "baseline_cgroup=$BASELINE_CGROUP" \
            "runtime=$RUNTIME" \
            "${baseline_args[@]}" || exit 1

        baseline_done_default=true

        echo ""
        sleep 5
    done
done

echo "All mapped Twitter trace benchmarks completed."
