#!/bin/bash
set -eu -o pipefail

restore_readahead() { :; }

cleanup_bg() {
    echo "[Cleanup] 清理后台进程..."

    stop_pcache_monitor 2>/dev/null || true
    stop_perf_monitor 2>/dev/null || true
    stop_memory_monitor 2>/dev/null || true
    restore_readahead 2>/dev/null || true

    # First try the PIDs captured from the background sudo commands.
    sudo kill -2 ${LOADER_PID:-0} 2>/dev/null || true
    sudo kill -2 ${DISPATCHER_PID:-0} 2>/dev/null || true
    sleep 2

    # Fallback: $! may be the sudo wrapper PID, and the actual loader/dispatcher
    # process can survive. Kill the real binaries by exact path when available.
    if [ -n "${POLICY_PATH:-}" ]; then
        sudo pkill -INT -f "$POLICY_PATH/a_user_loader.out" 2>/dev/null || true
        sudo pkill -INT -f "$POLICY_PATH/a_dispatcher.out" 2>/dev/null || true
        sleep 2

        sudo pkill -TERM -f "$POLICY_PATH/a_user_loader.out" 2>/dev/null || true
        sudo pkill -TERM -f "$POLICY_PATH/a_dispatcher.out" 2>/dev/null || true
    fi
    sleep 1
}
trap 'status=$?; cleanup_bg; exit $status' EXIT

usage() {
    echo "用法: $0 <benchmark> <policy> [cgroup_size] [test_memory=true|false] [memory_interval=<seconds>] [test_perf=true|false] [disable_readahead=true|false]"
    echo ""
    echo "  benchmark:    YCSB 负载名称，逗号分隔或单个"
    echo "                ycsb_a, ycsb_b, ycsb_c, ycsb_d, ycsb_e, ycsb_f"
    echo "                uniform, uniform_read_write, mixed_get_scan"
    echo ""
    echo "  policy:       fifo, lru, lfu, arc, lhd, s3fifo"
    echo ""
    echo "  cgroup_size:  内存限制 (默认 10G)，如 5G, 2G"
    echo "  test_memory: 默认 false；有 LevelDB 对齐统计时默认只保留30秒快照，否则使用独立采样"
    echo "  memory_poll: auto（默认）|true（额外独立采样）|false；独立采样还需 test_memory=true"
    echo "  memory_interval: 默认 5 秒；test_memory=true 时生效"
    echo "  test_perf:    默认 false；true 时每阶段在 warmup 后 attach run_leveldb 采 perf record，并采 page-cache add/readahead tracepoint"
    echo "  disable_readahead: 默认 false；true 时临时将 DB 所在块设备 readahead 设为 0，退出时恢复"
    echo ""
    echo "示例:"
    echo "  $0 ycsb_a lfu"
    echo "  $0 ycsb_a lfu 5G"
    echo "  $0 ycsb_a lfu 3G test_memory=true test_perf=true"
    echo "  $0 ycsb_a s3fifo 3G test_memory=true disable_readahead=true"
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

if ! uname -r | grep -q "cache-ext"; then
    echo "This script is intended to be run on a cache_ext kernel."
    echo "Please switch to the cache_ext kernel and try again."
    exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
RESULTS_PATH="$BASE_DIR/results"
POLICY_PATH="$BASE_DIR/policies"
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_PATH="/root/data/leveldb_db"

BENCHMARK="$1"
POLICY_NAME="$2"

ITERATIONS=1
CGROUP_SIZE="10G"
TEST_MEMORY=false
MEMORY_POLL="${MEMORY_POLL:-auto}"
TEST_PERF=false
DISABLE_READAHEAD=false
MEMORY_SAMPLE_INTERVAL=5
RUNTIME_SECONDS=240
WARMUP_RUNTIME_SECONDS=45
BASELINE_CGROUP_NAME="baseline_test"
CACHE_EXT_CGROUP_NAME="cache_ext_test"

for arg in "${@:3}"; do
    case "$arg" in
        test_leveldb_io=*|sst_sample_every=*|diagnostic_*=*)
            echo "[Error] Retired diagnostics option: $arg; use test_memory=true" >&2; usage ;;
        memory_poll=*) MEMORY_POLL="${arg#*=}" ;;
        test_memory|test_memory=true|--test-memory|true)
            TEST_MEMORY=true
            ;;
        test_memory=false|--no-test-memory|false)
            TEST_MEMORY=false
            ;;
        test_perf|test_perf=true|--test-perf)
            TEST_PERF=true
            ;;
        test_perf=false|--no-test-perf)
            TEST_PERF=false
            ;;
        disable_readahead|disable_readahead=true|--disable-readahead)
            DISABLE_READAHEAD=true
            ;;
        disable_readahead=false|--no-disable-readahead)
            DISABLE_READAHEAD=false
            ;;
        memory_interval=*|memory_sample_interval=*)
            MEMORY_SAMPLE_INTERVAL="${arg#*=}"
            if ! [[ "$MEMORY_SAMPLE_INTERVAL" =~ ^[0-9]+$ ]] || [ "$MEMORY_SAMPLE_INTERVAL" -le 0 ]; then
                echo "[Error] memory_interval 必须是正整数秒数: $arg"
                usage
            fi
            ;;
        "")
            ;;
        *)
            if [ "$CGROUP_SIZE" != "10G" ]; then
                echo "[Error] 重复或无法识别的参数: $arg"
                usage
            fi
            CGROUP_SIZE="$arg"
            ;;
    esac
done

source "$BASE_DIR/eval/leveldb_io_monitor.sh"
resolve_memory_poll
check_leveldb_io_binary

run_benchmark_with_io() {
    local stage="$1"
    shift
    if [ "$TEST_MEMORY" = true ]; then
        local mode=no_perf
        if [ "$TEST_PERF" = true ]; then mode=perf; fi
        run_with_leveldb_io "$stage" \
            "$RESULTS_PATH/ycsb_spc_${POLICY_NAME}_${BENCHMARK_TAG}_${CGROUP_SIZE_TAG}" \
            "$mode" "$@"
    else
        "${BASE_CMD[@]}" "$@"
    fi
}

# 如果数据库目录不存在或为空，自动初始化
GENERATE_CONFIG="$YCSB_PATH/leveldb/config/generate_db.yaml"
if [ ! -f "$DB_PATH/CURRENT" ]; then
    echo "[Info] LevelDB 数据库不存在，正在初始化..."
    mkdir -p "$DB_PATH"
    sed -i "s|data_dir:.*|data_dir: \"$DB_PATH\"|" "$GENERATE_CONFIG"
    "$YCSB_PATH/build/init_leveldb" "$GENERATE_CONFIG"
    echo "[Done] 数据库初始化完成: $DB_PATH"
fi

case "$POLICY_NAME" in
    fifo|lru|lfu|arc|lhd|s3fifo)
    ;;
    *)
    echo "[Error] 无效的策略: $POLICY_NAME"
    usage
    ;;
esac

mkdir -p "$RESULTS_PATH"

sanitize_filename_component() {
    local value="$1"
    value="${value//[^A-Za-z0-9._-]/_}"
    if [ -z "$value" ]; then
        value="auto"
    fi
    echo "$value"
}

BENCHMARK_TAG=$(sanitize_filename_component "$(echo "$BENCHMARK" | tr ',' '_')")
CGROUP_SIZE_TAG=$(sanitize_filename_component "$CGROUP_SIZE")
if [ "$DISABLE_READAHEAD" = "true" ]; then
    CGROUP_SIZE_TAG="${CGROUP_SIZE_TAG}_nora"
fi
RESULT_FILE="$RESULTS_PATH/ycsb_spc_${POLICY_NAME}_${BENCHMARK_TAG}_${CGROUP_SIZE_TAG}.json"

echo "[Info] 所选 YCSB 负载: $BENCHMARK"
echo "[Info] 所选 cache_ext 策略: $POLICY_NAME"
echo "[Info] cgroup size: $CGROUP_SIZE"
echo "[Info] memory/io 采样: $TEST_MEMORY"
echo "[Info] Independent memory polling: $MEMORY_POLL_ENABLED (memory_poll=$MEMORY_POLL, interval=${MEMORY_SAMPLE_INTERVAL}s); Benchmark aligned snapshots: $TEST_MEMORY (30s)"
echo "[Info] perf record 采样: $TEST_PERF"
echo "[Info] page-cache tracepoint 采样: $TEST_PERF"
echo "[Info] 禁用块设备 readahead: $DISABLE_READAHEAD"
echo "[Info] 结果保存至: $RESULT_FILE"

MEMORY_MONITOR_PID=""
PERF_MONITOR_PID=""
PCACHE_MONITOR_PID=""
READAHEAD_DEVICE=""
READAHEAD_ORIG_VALUE=""
READAHEAD_CONFIGURED=false
PERF_RECORD_SECONDS=60
PERF_START_DELAY_SECONDS="$WARMUP_RUNTIME_SECONDS"
MEMORY_STAT_PATTERN='^(anon|file|file_dirty|file_writeback|inactive_file|active_file|slab|kernel_stack|pagetables|pgscan|pgsteal) '
PCACHE_EVENTS="filemap:mm_filemap_add_to_page_cache,filemap:mm_filemap_add_to_page_cache_prefetch"

resolve_db_readahead_device() {
    local source
    source=$(findmnt -no SOURCE -T "$DB_PATH" 2>/dev/null | head -n 1 || true)
    if [ -z "$source" ] || [[ "$source" != /dev/* ]]; then
        return 1
    fi
    readlink -f "$source" 2>/dev/null || echo "$source"
}

disable_readahead_if_requested() {
    if [ "$DISABLE_READAHEAD" != "true" ]; then
        return 0
    fi

    local device
    device=$(resolve_db_readahead_device || true)
    if [ -z "$device" ]; then
        echo "[Error] 无法定位 DB 所在块设备，不能安全禁用 readahead: $DB_PATH"
        exit 1
    fi

    READAHEAD_ORIG_VALUE=$(sudo blockdev --getra "$device")
    READAHEAD_DEVICE="$device"
    READAHEAD_CONFIGURED=true

    echo "[Info] 临时禁用 DB 块设备 readahead: device=$READAHEAD_DEVICE orig=$READAHEAD_ORIG_VALUE"
    sudo blockdev --setra 0 "$READAHEAD_DEVICE"
    echo "[Info] 当前 readahead: $(sudo blockdev --getra "$READAHEAD_DEVICE")"
}

restore_readahead() {
    if [ "$READAHEAD_CONFIGURED" != "true" ]; then
        return 0
    fi

    echo "[Cleanup] 恢复 DB 块设备 readahead: device=$READAHEAD_DEVICE value=$READAHEAD_ORIG_VALUE"
    sudo blockdev --setra "$READAHEAD_ORIG_VALUE" "$READAHEAD_DEVICE" 2>/dev/null || true
    READAHEAD_CONFIGURED=false
}

start_memory_monitor() {
    local stage="$1"
    local cgroup_name="$2"
    local cgroup_path="/sys/fs/cgroup/$cgroup_name"
    local log_file="$RESULTS_PATH/ycsb_spc_${POLICY_NAME}_${BENCHMARK_TAG}_${CGROUP_SIZE_TAG}_mem_${stage}.log"

    stop_memory_monitor 2>/dev/null || true

    if [ "$MEMORY_POLL_ENABLED" != "true" ]; then
        echo "[Info] Independent memory polling disabled: stage=$stage; Benchmark snapshots=$TEST_MEMORY"
        echo "# disabled: memory_poll=$MEMORY_POLL test_memory=$TEST_MEMORY snapshots=$TEST_MEMORY; use leveldb_io JSONL/io_windows CSV" > "$log_file"
        return 0
    fi

    echo "[Info] 启动 memory/io/pressure 采样: stage=$stage cgroup=$cgroup_name interval=${MEMORY_SAMPLE_INTERVAL}s"
    echo "[Info] memory/io/pressure 日志: $log_file"

    (
        echo "# stage=$stage"
        echo "# cgroup=$cgroup_name"
        echo "# cgroup_path=$cgroup_path"
        echo "# interval_seconds=$MEMORY_SAMPLE_INTERVAL"
        echo "# fields: timestamp memory.current selected memory.stat memory.pressure io.stat cache_ext_reclaim.stat"
        echo "# cache_ext_reclaim.stat: local cgroup cumulative counters; *_pages in PAGE_SIZE units; keep_* are exclusive reasons; use interval deltas"
        while true; do
            if [ -d "$cgroup_path" ]; then
                echo "timestamp $(date '+%F %T')"
                if [ -f "$cgroup_path/memory.current" ]; then
                    echo -n "memory.current "
                    cat "$cgroup_path/memory.current"
                else
                    echo "memory.current missing"
                fi
                if [ -f "$cgroup_path/memory.stat" ]; then
                    grep -E "$MEMORY_STAT_PATTERN" "$cgroup_path/memory.stat" || true
                else
                    echo "memory.stat missing"
                fi
                if [ -f "$cgroup_path/memory.pressure" ]; then
                    sed 's/^/memory.pressure /' "$cgroup_path/memory.pressure" || true
                else
                    echo "memory.pressure missing"
                fi
                if [ -f "$cgroup_path/io.stat" ]; then
                    sed 's/^/io.stat /' "$cgroup_path/io.stat" || true
                else
                    echo "io.stat missing"
                fi
                if [ -f "$cgroup_path/memory.cache_ext_reclaim_stat" ]; then
                    sed 's/^/cache_ext_reclaim.stat /' "$cgroup_path/memory.cache_ext_reclaim_stat" || true
                else
                    echo "cache_ext_reclaim.stat unavailable"
                fi
                echo
            else
                echo "timestamp $(date '+%F %T')"
                echo "cgroup_missing $cgroup_path"
                echo
            fi
            sleep "$MEMORY_SAMPLE_INTERVAL"
        done
    ) > "$log_file" 2>&1 &
    MEMORY_MONITOR_PID=$!
}

stop_memory_monitor() {
    if [ -n "${MEMORY_MONITOR_PID:-}" ]; then
        kill "$MEMORY_MONITOR_PID" 2>/dev/null || true
        wait "$MEMORY_MONITOR_PID" 2>/dev/null || true
        MEMORY_MONITOR_PID=""
    fi
}

find_run_leveldb_pid_for_cgroup() {
    local cgroup_name="$1"
    local pid

    for pid in $(pgrep -x run_leveldb 2>/dev/null || true); do
        if [ -r "/proc/$pid/cgroup" ] && grep -q "/${cgroup_name}\\($\\|/\\)" "/proc/$pid/cgroup"; then
            echo "$pid"
            return 0
        fi
    done

    return 1
}

start_pcache_monitor() {
    local stage="$1"
    local cgroup_name="$2"
    local log_file="$RESULTS_PATH/ycsb_spc_${POLICY_NAME}_${BENCHMARK_TAG}_${CGROUP_SIZE_TAG}_pcache_${stage}.log"

    stop_pcache_monitor 2>/dev/null || true

    if [ "$TEST_PERF" != "true" ]; then
        return 0
    fi

    echo "[Info] 启动 page-cache tracepoint 采样: stage=$stage cgroup=$cgroup_name delay=${WARMUP_RUNTIME_SECONDS}s duration=${RUNTIME_SECONDS}s"
    echo "[Info] page-cache tracepoint 日志: $log_file"

    (
        set +e
        echo "# stage=$stage"
        echo "# cgroup=$cgroup_name"
        echo "# start_delay_seconds=$WARMUP_RUNTIME_SECONDS"
        echo "# duration_seconds=$RUNTIME_SECONDS"
        echo "# events=$PCACHE_EVENTS"
        echo "# note: raw event counts only; add includes write allocations, and readahead may include the demanded page. add-prefetch is NOT a demand-miss count."
        echo "# scope: PID-attached perf window, not the phase-aligned LevelDB/cgroup window; do not normalize by whole-run ops."

        local pid=""
        local waited=0
        while [ "$waited" -lt 300 ]; do
            pid=$(find_run_leveldb_pid_for_cgroup "$cgroup_name" || true)
            if [ -n "$pid" ]; then
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done

        if [ -z "$pid" ]; then
            echo "[Pcache] run_leveldb pid not found for cgroup=$cgroup_name after ${waited}s"
            exit 0
        fi

        echo "[Pcache] attach pid=$pid at $(date '+%F %T')"
        if [ "$WARMUP_RUNTIME_SECONDS" -gt 0 ]; then
            echo "[Pcache] waiting ${WARMUP_RUNTIME_SECONDS}s for warmup to finish"
            sleep "$WARMUP_RUNTIME_SECONDS"
        fi

        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[Pcache] run_leveldb pid=$pid exited before perf stat start"
            exit 0
        fi

        echo "[Pcache] perf stat start at $(date '+%F %T')"
        sudo perf stat -x, -e "$PCACHE_EVENTS" -p "$pid" -- sleep "$RUNTIME_SECONDS"
        stat_status=$?
        echo "[Pcache] perf stat exit status=$stat_status at $(date '+%F %T')"
    ) > "$log_file" 2>&1 &
    PCACHE_MONITOR_PID=$!
}

stop_pcache_monitor() {
    if [ -n "${PCACHE_MONITOR_PID:-}" ]; then
        kill "$PCACHE_MONITOR_PID" 2>/dev/null || true
        wait "$PCACHE_MONITOR_PID" 2>/dev/null || true
        PCACHE_MONITOR_PID=""
    fi
}

start_perf_monitor() {
    local stage="$1"
    local cgroup_name="$2"
    local log_file="$RESULTS_PATH/ycsb_spc_${POLICY_NAME}_${BENCHMARK_TAG}_${CGROUP_SIZE_TAG}_perf_${stage}.log"
    local data_file="$RESULTS_PATH/ycsb_spc_${POLICY_NAME}_${BENCHMARK_TAG}_${CGROUP_SIZE_TAG}_perf_${stage}.data"

    stop_perf_monitor 2>/dev/null || true

    if [ "$TEST_PERF" != "true" ]; then
        return 0
    fi

    echo "[Info] 启动 perf record watcher: stage=$stage cgroup=$cgroup_name delay=${PERF_START_DELAY_SECONDS}s duration=${PERF_RECORD_SECONDS}s"
    echo "[Info] perf 日志: $log_file"
    echo "[Info] perf data: $data_file"

    (
        set +e
        echo "# stage=$stage"
        echo "# cgroup=$cgroup_name"
        echo "# start_delay_seconds=$PERF_START_DELAY_SECONDS"
        echo "# duration_seconds=$PERF_RECORD_SECONDS"
        echo "# data_file=$data_file"

        local pid=""
        local waited=0
        while [ "$waited" -lt 300 ]; do
            pid=$(find_run_leveldb_pid_for_cgroup "$cgroup_name" || true)
            if [ -n "$pid" ]; then
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done

        if [ -z "$pid" ]; then
            echo "[Perf] run_leveldb pid not found for cgroup=$cgroup_name after ${waited}s"
            exit 0
        fi

        echo "[Perf] attach pid=$pid at $(date '+%F %T')"
        if [ "$PERF_START_DELAY_SECONDS" -gt 0 ]; then
            echo "[Perf] waiting ${PERF_START_DELAY_SECONDS}s for warmup to finish"
            sleep "$PERF_START_DELAY_SECONDS"
        fi

        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[Perf] run_leveldb pid=$pid exited before perf record start"
            exit 0
        fi

        echo "[Perf] record start at $(date '+%F %T')"
        sudo perf record -g -o "$data_file" -p "$pid" -- sleep "$PERF_RECORD_SECONDS"
        perf_status=$?
        echo "[Perf] record exit status=$perf_status at $(date '+%F %T')"

        if [ -s "$data_file" ]; then
            echo
            echo "===== perf report --stdio ====="
            sudo perf report --stdio -i "$data_file" --percent-limit 0.5
            report_status=$?
            echo "[Perf] report exit status=$report_status"
        else
            echo "[Perf] data file missing or empty: $data_file"
        fi
    ) > "$log_file" 2>&1 &
    PERF_MONITOR_PID=$!
}

stop_perf_monitor() {
    if [ -n "${PERF_MONITOR_PID:-}" ]; then
        kill "$PERF_MONITOR_PID" 2>/dev/null || true
        wait "$PERF_MONITOR_PID" 2>/dev/null || true
        PERF_MONITOR_PID=""
    fi
}

# Phase-aligned io_windows CSV replaces the old estimated_ops validation summary.
# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
    echo "Failed to disable MGLRU. Please check the script."
    exit 1
fi

disable_readahead_if_requested

# 清除旧数据
rm -f "$RESULT_FILE"

BASE_CMD=(
    python3 "$BENCH_PATH/a_bench_leveldb.py"
    --cpu 8
    --results-file "$RESULT_FILE"
    --leveldb-db "$DB_PATH"
    --fadvise-hints ""
    --iterations "$ITERATIONS"
    --bench-binary-dir "$YCSB_PATH/build"
    --benchmark "$BENCHMARK"
    --cgroup-size "$CGROUP_SIZE"
)

# ====================================================================
# 阶段 1/3：运行原生 Linux 基线测试 (Baseline)
# ====================================================================
echo "--------------------------------------------------------"
echo "[阶段 1/3] 运行: 原生 Linux 默认页面缓存 (Baseline)"
echo "--------------------------------------------------------"
start_memory_monitor "baseline" "$BASELINE_CGROUP_NAME"
start_pcache_monitor "baseline" "$BASELINE_CGROUP_NAME"
start_perf_monitor "baseline" "$BASELINE_CGROUP_NAME"
run_benchmark_with_io baseline --default-only --policy-loader ""
stop_perf_monitor
stop_pcache_monitor
stop_memory_monitor

# ====================================================================
# 阶段 2/3：运行 cache_ext 独立策略测试
# ====================================================================
echo "--------------------------------------------------------"
echo "[阶段 2/3] 运行: cache_ext 独立加载 $POLICY_NAME 策略"
echo "--------------------------------------------------------"
start_memory_monitor "direct_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
start_pcache_monitor "direct_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
start_perf_monitor "direct_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
run_benchmark_with_io "direct_${POLICY_NAME}" --policy-loader "$POLICY_PATH/cache_ext_${POLICY_NAME}.out"
stop_perf_monitor
stop_pcache_monitor
stop_memory_monitor

# ====================================================================
# 阶段 3/3：运行 cache_ext Dispatcher + 策略测试
# ====================================================================
echo "--------------------------------------------------------"
echo "[阶段 3/3] 运行: cache_ext Dispatcher + $POLICY_NAME"
echo "--------------------------------------------------------"
CGROUP_TEST_PATH="/sys/fs/cgroup/cache_ext_test"
sudo mkdir -p "$CGROUP_TEST_PATH"

echo "[Info] 预创建 temp 数据库，确保 watch_dir 存在..."
rsync -avpl --delete "${DB_PATH}/" "${DB_PATH}_temp" > /dev/null 2>&1

echo "[Info] 启动后台 Dispatcher..."
sudo "$POLICY_PATH/a_dispatcher.out" -w "${DB_PATH}_temp" -c "$CGROUP_TEST_PATH" > dispatcher_bench.log 2>&1 &
DISPATCHER_PID=$!
sleep 2

echo "[Info] 启动后台 User Loader ($POLICY_NAME)..."
sudo "$POLICY_PATH/a_user_loader.out" -c "$CGROUP_TEST_PATH" -o "$POLICY_NAME" > loader_bench.log 2>&1 &
LOADER_PID=$!
sleep 2

echo "[Info] 正在运行 YCSB 压测..."
start_memory_monitor "dispatcher_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
start_pcache_monitor "dispatcher_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
start_perf_monitor "dispatcher_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
run_benchmark_with_io "dispatcher_${POLICY_NAME}" --policy-loader ""
stop_perf_monitor
stop_pcache_monitor
stop_memory_monitor

# Per-stage io_windows CSV replaces the unaligned validation summary.

echo "[Info] 压测结束，清理 Dispatcher 和 Loader 后台进程..."
sudo kill -2 $LOADER_PID 2>/dev/null || true
sleep 2
sudo kill -2 $DISPATCHER_PID 2>/dev/null || true
sleep 2

# ====================================================================
# 收尾工作
# ====================================================================
echo "--------------------------------------------------------"
echo "[Info] 测试执行完毕，清理临时资源..."

TEMP_DB="${DB_PATH}_temp"
if [ -d "$TEMP_DB" ]; then
    rm -rf "$TEMP_DB"
    echo "[Done] LevelDB temp directory cleaned: $TEMP_DB"
fi

if [ -d "/sys/fs/bpf/cache_ext" ]; then
    sudo rm -rf /sys/fs/bpf/cache_ext
    echo "[Done] eBPF maps unpinned."
fi
if [ -d "$CGROUP_TEST_PATH" ]; then
    sudo rmdir "$CGROUP_TEST_PATH" 2>/dev/null || true
    echo "[Done] Cgroup cleaned up."
fi

echo "Benchmark completed!"
echo "3组对比数据 (Baseline / $POLICY_NAME / Dispatcher+$POLICY_NAME) 已保存至:"
echo "-> $RESULT_FILE"
