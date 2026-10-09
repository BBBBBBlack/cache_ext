#!/bin/bash
set -eu -o pipefail

ORIG_STTY=""
if [ -t 0 ]; then
    ORIG_STTY=$(stty -g 2>/dev/null || true)
fi

restore_readahead() { :; }

cleanup_bg() {
    echo "[Cleanup] 清理后台进程..."

    stop_pcache_monitor 2>/dev/null || true
    stop_perf_monitor 2>/dev/null || true
    stop_memory_monitor 2>/dev/null || true
    restore_readahead 2>/dev/null || true

    # First try the PIDs captured from the background sudo commands.
    if [ -n "${LOADER_PID:-}" ]; then
        sudo kill -2 "$LOADER_PID" 2>/dev/null || true
    fi
    if [ -n "${DISPATCHER_PID:-}" ]; then
        sudo kill -2 "$DISPATCHER_PID" 2>/dev/null || true
    fi
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

    if [ -n "${ORIG_STTY:-}" ] && [ -t 0 ]; then
        stty "$ORIG_STTY" 2>/dev/null || true
    fi
}
usage() {
    echo "用法: $0 <cluster> <policy> [cgroup_size] [limit-nr-op|ignore-nr-op] [test_memory=true|false] [memory_interval=<seconds>] [perf_mode=none|record|tracepoint|both] [test_perf=true|false] [results_dir=<path>] [runtime=<seconds>] [warmup=<seconds>] [cache_ext_cgroup=<name>] [baseline_cgroup=<name>] [disable_readahead=true|false] [readahead_kb=<default|N>] [skip_baseline=true|false]"
    echo ""
    echo "  cluster:      Twitter trace cluster 编号，如 17, 18, 24, 34, 52"
    echo ""
    echo "  policy:       fifo, lru, lfu, arc, s3fifo, lhd"
    echo ""
    echo "  cgroup_size:  内存限制 (默认自动计算)，如 200M, 1G"
    echo ""
    echo "  ignore-nr-op: 默认值，忽略 nr_op/nr_warmup_op，只按 runtime_seconds 或 trace EOF 停止"
    echo "  limit-nr-op:  Twitter bench 到 nr_op 或 runtime_seconds 任一条件满足即停止"
    echo ""
    echo "  test_memory: 默认 false；开启内存/IO统计；默认保留30秒对齐快照和吞吐"
    echo "  memory_poll: auto（默认，避免重复采样）|true（额外独立采样）|false；独立采样还需 test_memory=true"
    echo "  memory_interval: 默认 5 秒；test_memory=true 时生效"
    echo "  perf_mode:    none=关闭 perf 监测；record=仅调用栈；tracepoint=仅 page-cache 事件计数；both=两者开启"
    echo "                record 采样 60 秒，tracepoint 计数 runtime 秒；均从发现进程后等待 warmup 秒开始"
    echo "                none 不影响独立的 test_memory 或 readahead 设置"
    echo "  test_perf:    兼容参数；true=both，false=none（默认）；显式 perf_mode 优先，不受参数顺序影响"
    echo "  results_dir: 默认 results；JSON 和所有监测日志按模式区分，另保留不带模式的最新 JSON 副本"
    echo ""
    echo "  runtime:      默认 240；写入 bench YAML 的 workload.runtime_seconds"
    echo "  warmup:       默认 45；写入 bench YAML 的 workload.warmup_runtime_seconds"
    echo ""
    echo "  cache_ext_cgroup: 默认 cache_ext_test；Direct/Dispatcher cache_ext 阶段使用的 cgroup 名"
    echo "  baseline_cgroup: 默认 baseline_test；Baseline 阶段使用的 cgroup 名"
    echo "  disable_readahead: 默认 false；true 时临时将 DB 所在块设备 readahead 设为 0，退出时恢复"
    echo "  readahead_kb: 默认 default，即不修改；传入非负整数 N 时临时将 DB 所在块设备 read_ahead_kb 设为 N，退出时恢复"
    echo "  skip_baseline: 默认 false；true 时跳过 Baseline 阶段；当前 JSON 中不会写入 baseline"
    echo ""
    echo "示例:"
    echo "  $0 17 s3fifo"
    echo "  $0 17 lfu 200M"
    echo "  $0 17 lfu 200M limit-nr-op"
    echo "  $0 17 lfu limit-nr-op"
    echo "  $0 17 lfu 64M test_memory=true"
    echo "  $0 17 lfu 64M test_memory=true memory_interval=2"
    echo "  $0 17 lfu 64M test_memory=true test_perf=true"
    echo "  $0 34 s3fifo 3G perf_mode=record test_memory=true runtime=3600"
    echo "  $0 34 s3fifo 3G perf_mode=tracepoint results_dir=/tmp/twitter-tracepoint"
    echo "  $0 17 lfu 64M runtime=500 warmup=60"
    echo "  $0 17 lfu 64M cache_ext_cgroup=cache_ext_test_a baseline_cgroup=baseline_test_a"
    echo "  $0 34 s3fifo 3G test_memory=true disable_readahead=true"
    echo "  $0 18 s3fifo 400M test_memory=true readahead_kb=64"
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
DB_DIRS=$(realpath "$BASE_DIR/../")

CLUSTER="$1"
POLICY_NAME="$2"
CGROUP_SIZE=""
TRACE_NR_OP_MODE="ignore-nr-op"
TEST_MEMORY=false
MEMORY_POLL="${MEMORY_POLL:-auto}"
TEST_PERF=false
PERF_MODE=""
MEMORY_SAMPLE_INTERVAL=5
RUNTIME_SECONDS=240
WARMUP_RUNTIME_SECONDS=45
CACHE_EXT_CGROUP_NAME="cache_ext_test"
BASELINE_CGROUP_NAME="baseline_test"
DISABLE_READAHEAD=false
READAHEAD_KB="default"
SKIP_BASELINE=false
for arg in "${@:3}"; do
    case "$arg" in
        test_leveldb_io=*|sst_sample_every=*|diagnostic_*=*)
            echo "[Error] Retired diagnostics option: $arg; use test_memory=true" >&2; usage ;;
        memory_poll=*) MEMORY_POLL="${arg#*=}" ;;
        limit-nr-op|ignore-nr-op)
            TRACE_NR_OP_MODE="$arg"
            ;;
        cache_ext_cgroup=*)
            CACHE_EXT_CGROUP_NAME="${arg#*=}"
            if [ -z "$CACHE_EXT_CGROUP_NAME" ] || [[ "$CACHE_EXT_CGROUP_NAME" == */* ]]; then
                echo "[Error] cache_ext_cgroup 不能为空，且不能包含 /: $arg"
                usage
            fi
            ;;
        baseline_cgroup=*)
            BASELINE_CGROUP_NAME="${arg#*=}"
            if [ -z "$BASELINE_CGROUP_NAME" ] || [[ "$BASELINE_CGROUP_NAME" == */* ]]; then
                echo "[Error] baseline_cgroup 不能为空，且不能包含 /: $arg"
                usage
            fi
            ;;
        runtime=*|runtime_seconds=*)
            RUNTIME_SECONDS="${arg#*=}"
            if ! [[ "$RUNTIME_SECONDS" =~ ^[0-9]+$ ]] || [ "$RUNTIME_SECONDS" -le 0 ]; then
                echo "[Error] runtime 必须是正整数秒数: $arg"
                usage
            fi
            ;;
        warmup=*|warmup_runtime_seconds=*)
            WARMUP_RUNTIME_SECONDS="${arg#*=}"
            if ! [[ "$WARMUP_RUNTIME_SECONDS" =~ ^[0-9]+$ ]]; then
                echo "[Error] warmup 必须是非负整数秒数: $arg"
                usage
            fi
            ;;
        memory_interval=*|memory_sample_interval=*)
            MEMORY_SAMPLE_INTERVAL="${arg#*=}"
            if ! [[ "$MEMORY_SAMPLE_INTERVAL" =~ ^[0-9]+$ ]] || [ "$MEMORY_SAMPLE_INTERVAL" -le 0 ]; then
                echo "[Error] memory_interval 必须是正整数秒数: $arg"
                usage
            fi
            ;;
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
        perf_mode=*)
            PERF_MODE="${arg#*=}"
            case "$PERF_MODE" in
                none|record|tracepoint|both) ;;
                *)
                    echo "[Error] perf_mode 必须是 none、record、tracepoint 或 both: $arg"
                    usage
                    ;;
            esac
            ;;
        results_dir=*)
            if [ -z "${arg#*=}" ]; then
                echo "[Error] results_dir 不能为空"
                usage
            fi
            RESULTS_PATH=$(realpath -m -- "${arg#*=}")
            ;;
        disable_readahead|disable_readahead=true|--disable-readahead)
            DISABLE_READAHEAD=true
            ;;
        disable_readahead=false|--no-disable-readahead)
            DISABLE_READAHEAD=false
            ;;
        readahead_kb=*|read_ahead_kb=*|readahead=*)
            READAHEAD_KB="${arg#*=}"
            if [ "$READAHEAD_KB" != "default" ] && ! [[ "$READAHEAD_KB" =~ ^[0-9]+$ ]]; then
                echo "[Error] readahead_kb 必须是 default 或非负整数 KB: $arg"
                usage
            fi
            ;;
        skip_baseline|skip_baseline=true|--skip-baseline)
            SKIP_BASELINE=true
            ;;
        skip_baseline=false|--no-skip-baseline)
            SKIP_BASELINE=false
            ;;
        "")
            ;;
        *)
            if [ -n "$CGROUP_SIZE" ]; then
                echo "[Error] 重复或无法识别的参数: $arg"
                usage
            fi
            CGROUP_SIZE="$arg"
            ;;
    esac
done

if [ -z "$PERF_MODE" ]; then
    if [ "$TEST_PERF" = "true" ]; then
        PERF_MODE=both
    else
        PERF_MODE=none
    fi
fi
TEST_PERF_RECORD=false
TEST_TRACEPOINT=false
case "$PERF_MODE" in
    record) TEST_PERF_RECORD=true ;;
    tracepoint) TEST_TRACEPOINT=true ;;
    both) TEST_PERF_RECORD=true; TEST_TRACEPOINT=true ;;
esac
RUN_MODE_TAG="$PERF_MODE"

ITERATIONS=1
source "$BASE_DIR/eval/leveldb_io_monitor.sh"
resolve_memory_poll
check_leveldb_io_binary
BENCHMARK="twitter_cluster${CLUSTER}_bench"
DB_PATH="$DB_DIRS/data/leveldb_twitter_cluster${CLUSTER}_db"
TRACES_DIR="$DB_DIRS/data/twitter/traces"

# 如果数据库目录不存在，自动用 init trace 初始化
INIT_CONFIG="$YCSB_PATH/leveldb/config/twitter_cluster${CLUSTER}_init.yaml"
INIT_TRACE="$TRACES_DIR/cluster${CLUSTER}_init.txt"
BENCH_TRACE="$TRACES_DIR/cluster${CLUSTER}_bench.txt"
COMPLETE_INIT_TRACE="$TRACES_DIR/cluster${CLUSTER}_init_complete.txt"
INIT_CONFIG_EFFECTIVE="/tmp/twitter_cluster${CLUSTER}_init_complete.yaml"
INIT_DONE_MARKER="$DB_PATH/.twitter_init_complete_with_bench_keys"

if [ ! -f "$BENCH_TRACE" ]; then
    echo "[Error] Bench trace 不存在: $BENCH_TRACE"
    exit 1
fi

if [ -f "$DB_PATH/CURRENT" ] && [ -f "$INIT_DONE_MARKER" ]; then
    echo "[Info] LevelDB 数据库已存在且带完整初始化 marker，跳过 init trace 检查: $DB_PATH"
else
    if [ ! -f "$INIT_CONFIG" ]; then
            echo "[Error] Init 配置文件不存在: $INIT_CONFIG"
            exit 1
    fi
    if [ ! -f "$INIT_TRACE" ]; then
        echo "[Error] Init trace 不存在: $INIT_TRACE"
        exit 1
    fi

    # 原始 Twitter init trace 不一定覆盖 bench trace 里的全部 key。
    # 这里生成 init ∪ bench_keys，保证后续 get/update 不会因为初始 DB 缺 key 而 NotFound。
    if [ ! -f "$COMPLETE_INIT_TRACE" ] || [ "$INIT_TRACE" -nt "$COMPLETE_INIT_TRACE" ] || [ "$BENCH_TRACE" -nt "$COMPLETE_INIT_TRACE" ]; then
        echo "[Info] 生成完整 init trace: $COMPLETE_INIT_TRACE"
        python3 "$BASE_DIR/eval/twitter/generate_init_complete_trace.py" "$INIT_TRACE" "$BENCH_TRACE" "$COMPLETE_INIT_TRACE"
    fi

    python3 - "$INIT_CONFIG" "$COMPLETE_INIT_TRACE" "$DB_PATH" "$INIT_CONFIG_EFFECTIVE" <<'PY'
import sys
import yaml

src_config, trace_file, db_path, dst_config = sys.argv[1:]
with open(src_config) as f:
    config = yaml.safe_load(f)

config["workload"]["trace_file"] = trace_file
config["workload"]["trace_type"] = "twitter_init"
config["leveldb"]["data_dir"] = db_path

with open(dst_config, "w") as f:
    yaml.safe_dump(config, f, sort_keys=False)
PY

    echo "[Info] LevelDB 数据库未完整初始化，正在导入完整 init trace..."
    rm -rf "$DB_PATH"
    mkdir -p "$DB_PATH"
    "$YCSB_PATH/build/init_leveldb" "$INIT_CONFIG_EFFECTIVE"
    if [ ! -f "$DB_PATH/CURRENT" ]; then
        echo "[Error] 数据库初始化失败"
        exit 1
    fi
    touch "$INIT_DONE_MARKER"
    echo "[Done] 数据库初始化完成: $DB_PATH ($(du -sh "$DB_PATH" | cut -f1))"
fi

case "$POLICY_NAME" in
    fifo|lru|lfu|arc|s3fifo|lhd)
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

CGROUP_SIZE_TAG=$(sanitize_filename_component "${CGROUP_SIZE:-auto}")
if [ "$DISABLE_READAHEAD" = "true" ]; then
    CGROUP_SIZE_TAG="${CGROUP_SIZE_TAG}_nora"
elif [ "$READAHEAD_KB" != "default" ]; then
    CGROUP_SIZE_TAG="${CGROUP_SIZE_TAG}_ra${READAHEAD_KB}KB"
fi
LEGACY_RESULT_FILE="$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}.json"
RESULT_FILE="${LEGACY_RESULT_FILE%.json}_${RUN_MODE_TAG}.json"

echo "[Info] Twitter cluster: $CLUSTER"
echo "[Info] 所选 cache_ext 策略: $POLICY_NAME"
echo "[Info] Twitter nr_op 模式: $TRACE_NR_OP_MODE"
echo "[Info] runtime_seconds: $RUNTIME_SECONDS"
echo "[Info] warmup_runtime_seconds: $WARMUP_RUNTIME_SECONDS"
echo "[Info] cache_ext cgroup: $CACHE_EXT_CGROUP_NAME"
echo "[Info] baseline cgroup: $BASELINE_CGROUP_NAME"
echo "[Info] memory/io 采样: $TEST_MEMORY"
echo "[Info] Independent memory polling: $MEMORY_POLL_ENABLED (memory_poll=$MEMORY_POLL, interval=${MEMORY_SAMPLE_INTERVAL}s); Benchmark aligned snapshots: $TEST_MEMORY (30s)"
echo "[Info] perf mode: $PERF_MODE"
echo "[Info] perf record 采样: $TEST_PERF_RECORD"
echo "[Info] page-cache tracepoint 采样: $TEST_TRACEPOINT"
echo "[Info] 禁用块设备 readahead: $DISABLE_READAHEAD"
echo "[Info] 块设备 readahead_kb: $READAHEAD_KB"
echo "[Info] 跳过 baseline: $SKIP_BASELINE"
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
    if [ -z "$source" ]; then
        return 1
    fi
    if [[ "$source" != /dev/* ]]; then
        return 1
    fi
    readlink -f "$source" 2>/dev/null || echo "$source"
}

disable_readahead_if_requested() {
    local target_kb="$READAHEAD_KB"
    if [ "$DISABLE_READAHEAD" = "true" ]; then
        target_kb=0
    fi

    if [ "$target_kb" = "default" ]; then
        return 0
    fi

    local device
    device=$(resolve_db_readahead_device || true)
    if [ -z "$device" ]; then
        echo "[Error] 无法定位 DB 所在块设备，不能安全设置 readahead: $DB_PATH"
        exit 1
    fi

    READAHEAD_ORIG_VALUE=$(sudo blockdev --getra "$device")
    READAHEAD_DEVICE="$device"
    READAHEAD_CONFIGURED=true

    local target_sectors=$((target_kb * 2))
    echo "[Info] 临时设置 DB 块设备 readahead: device=$READAHEAD_DEVICE orig_sectors=$READAHEAD_ORIG_VALUE target_kb=$target_kb target_sectors=$target_sectors"
    sudo blockdev --setra "$target_sectors" "$READAHEAD_DEVICE"
    echo "[Info] 当前 readahead: sectors=$(sudo blockdev --getra "$READAHEAD_DEVICE")"
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
    local log_file="$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}_mem_${RUN_MODE_TAG}_${stage}.log"
    local throughput_log="$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}_throughput_${RUN_MODE_TAG}_${stage}.log"

    stop_memory_monitor 2>/dev/null || true

    if [ "$MEMORY_POLL_ENABLED" != "true" ]; then
        echo "[Info] Independent memory polling disabled: stage=$stage; Benchmark snapshots=$TEST_MEMORY"
        # Replace a stale log, so a rerun cannot be mistaken for old 5s samples.
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
        echo "# throughput_log=$throughput_log"
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

run_benchmark_with_throughput() {
    local stage="$1"
    shift

    if [ "$TEST_MEMORY" = true ]; then
        run_with_leveldb_io "$stage" \
            "$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}" \
            "$RUN_MODE_TAG" "$@"
        return
    fi

    if [ "$TEST_MEMORY" != "true" ]; then
        "${BASE_CMD[@]}" "$@"
        return
    fi

    local log_file="$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}_throughput_${RUN_MODE_TAG}_${stage}.log"
    echo "[Info] 每 30 秒 Trace 吞吐日志: $log_file"

    # My-YCSB reports a 10-second interval throughput at each Trace epoch.
    # Aggregate three successive measurement epochs; exclude warmup and epoch 0.
    PYTHONUNBUFFERED=1 "${BASE_CMD[@]}" "$@" 2>&1 | awk -v log_file="$log_file" -v stage="$stage" '
        BEGIN {
            print "# stage=" stage > log_file
            print "# fields: timestamp stage elapsed_seconds interval_seconds throughput_ops_s" >> log_file
            print "# three consecutive 10-second Trace reports per 30-second window; warmup and epoch 0 excluded" >> log_file
            fflush(log_file)
        }
        {
            print
            fflush()
            if ($0 !~ /^Trace \(epoch [0-9]+,/ || index($0, "total throughput ") == 0)
                next

            epoch = $0
            sub(/^Trace \(epoch /, "", epoch)
            sub(/,.*/, "", epoch)
            if (epoch !~ /^[0-9]+$/ || epoch == 0)
                next

            throughput = $0
            sub(/^.*total throughput /, "", throughput)
            sub(/ ops\/sec.*$/, "", throughput)
            if (throughput !~ /^[0-9]+([.][0-9]+)?$/)
                next

            sum += throughput
            count++
            if (count == 3) {
                "date -u +%Y-%m-%dT%H:%M:%SZ" | getline timestamp
                close("date -u +%Y-%m-%dT%H:%M:%SZ")
                printf "timestamp=%s stage=%s elapsed_seconds=%d interval_seconds=30 throughput_ops_s=%.2f\n", timestamp, stage, epoch * 10, sum / 3 >> log_file
                fflush(log_file)
                sum = 0
                count = 0
            }
        }
    '
}

start_pcache_monitor() {
    local stage="$1"
    local cgroup_name="$2"
    local log_file="$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}_pcache_${RUN_MODE_TAG}_${stage}.log"

    stop_pcache_monitor 2>/dev/null || true

    if [ "$TEST_TRACEPOINT" != "true" ]; then
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
        echo "# command: sleep $WARMUP_RUNTIME_SECONDS; perf stat -x, -e $PCACHE_EVENTS -p <run_leveldb_pid> -- sleep $RUNTIME_SECONDS"

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

start_perf_monitor() {
    local stage="$1"
    local cgroup_name="$2"
    local log_file="$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}_perf_${RUN_MODE_TAG}_${stage}.log"
    local data_file="$RESULTS_PATH/twitter_spc_${POLICY_NAME}_cluster${CLUSTER}_${CGROUP_SIZE_TAG}_perf_${RUN_MODE_TAG}_${stage}.data"

    stop_perf_monitor 2>/dev/null || true

    if [ "$TEST_PERF_RECORD" != "true" ]; then
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
        echo "# command: sleep $PERF_START_DELAY_SECONDS; perf record -g -p <run_leveldb_pid> -- sleep $PERF_RECORD_SECONDS"

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

CGROUP_SIZE_ARGS=()
if [ -n "$CGROUP_SIZE" ]; then
    CGROUP_SIZE_ARGS=(--cgroup-size "$CGROUP_SIZE")
fi

TRACE_NR_OP_ARGS=()
if [ "$TRACE_NR_OP_MODE" = "limit-nr-op" ]; then
    TRACE_NR_OP_ARGS=(--limit-trace-nr-op)
fi

BASE_CMD=(
    python3 "$BENCH_PATH/a_bench_twitter_trace.py"
    --cpu 8
    --results-file "$RESULT_FILE"
    --leveldb-db "$DB_PATH"
    --iterations "$ITERATIONS"
    --bench-binary-dir "$YCSB_PATH/build"
    --twitter-traces-dir "$TRACES_DIR"
    --benchmark "$BENCHMARK"
    --runtime-seconds "$RUNTIME_SECONDS"
    --warmup-runtime-seconds "$WARMUP_RUNTIME_SECONDS"
    --cache-ext-cgroup "$CACHE_EXT_CGROUP_NAME"
    --baseline-cgroup "$BASELINE_CGROUP_NAME"
    "${CGROUP_SIZE_ARGS[@]}"
    "${TRACE_NR_OP_ARGS[@]}"
)

# ====================================================================
# 阶段 1/3：运行原生 Linux 基线测试 (Baseline)
# ====================================================================
if [ "$SKIP_BASELINE" = "true" ]; then
    echo "--------------------------------------------------------"
    echo "[阶段 1/3] 跳过: 原生 Linux 默认页面缓存 (Baseline)"
    echo "[Info] 当前 JSON 不写入 baseline 结果"
    echo "--------------------------------------------------------"
else
    echo "--------------------------------------------------------"
    echo "[阶段 1/3] 运行: 原生 Linux 默认页面缓存 (Baseline)"
    echo "--------------------------------------------------------"
    start_memory_monitor "baseline" "$BASELINE_CGROUP_NAME"
    start_pcache_monitor "baseline" "$BASELINE_CGROUP_NAME"
    start_perf_monitor "baseline" "$BASELINE_CGROUP_NAME"
    run_benchmark_with_throughput "baseline" --default-only --policy-loader ""
    stop_perf_monitor
    stop_pcache_monitor
    stop_memory_monitor
fi

# ====================================================================
# 阶段 2/3：运行 cache_ext 独立策略测试
# ====================================================================
echo "--------------------------------------------------------"
echo "[阶段 2/3] 运行: cache_ext 独立加载 $POLICY_NAME 策略"
echo "--------------------------------------------------------"
start_memory_monitor "direct_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
start_pcache_monitor "direct_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
start_perf_monitor "direct_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
run_benchmark_with_throughput "direct_${POLICY_NAME}" --policy-loader "$POLICY_PATH/cache_ext_${POLICY_NAME}.out"
stop_perf_monitor
stop_pcache_monitor
stop_memory_monitor

# ====================================================================
# 阶段 3/3：运行 cache_ext Dispatcher + 策略测试
# ====================================================================
# echo "--------------------------------------------------------"
# echo "[阶段 3/3] 运行: cache_ext Dispatcher + $POLICY_NAME"
# echo "--------------------------------------------------------"
# CGROUP_TEST_PATH="/sys/fs/cgroup/$CACHE_EXT_CGROUP_NAME"
# sudo mkdir -p "$CGROUP_TEST_PATH"

# echo "[Info] 预创建 temp 数据库，确保 watch_dir 存在..."
# rsync -avpl --delete "${DB_PATH}/" "${DB_PATH}_temp" > /dev/null 2>&1

# echo "[Info] 启动后台 Dispatcher..."
# sudo "$POLICY_PATH/a_dispatcher.out" -w "${DB_PATH}_temp" -c "$CGROUP_TEST_PATH" > dispatcher_bench.log 2>&1 &
# DISPATCHER_PID=$!
# sleep 2

# echo "[Info] 启动后台 User Loader ($POLICY_NAME)..."
# sudo "$POLICY_PATH/a_user_loader.out" -c "$CGROUP_TEST_PATH" -o "$POLICY_NAME" > loader_bench.log 2>&1 &
# LOADER_PID=$!
# sleep 2

# echo "[Info] 正在运行 Twitter trace 压测..."
# start_memory_monitor "dispatcher_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
# start_pcache_monitor "dispatcher_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
# start_perf_monitor "dispatcher_${POLICY_NAME}" "$CACHE_EXT_CGROUP_NAME"
# "${BASE_CMD[@]}" --policy-loader ""
# stop_perf_monitor
# stop_pcache_monitor
# stop_memory_monitor

# echo "[Info] 压测结束，清理 Dispatcher 和 Loader 后台进程..."
# sudo kill -2 $LOADER_PID 2>/dev/null || true
# sleep 2
# sudo kill -2 $DISPATCHER_PID 2>/dev/null || true
# sleep 2

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
if [ -n "${CGROUP_TEST_PATH:-}" ] && [ -d "$CGROUP_TEST_PATH" ]; then
    sudo rmdir "$CGROUP_TEST_PATH" 2>/dev/null || true
    echo "[Done] Cgroup cleaned up: $CGROUP_TEST_PATH"
fi
for cgroup_name in "${CACHE_EXT_CGROUP_NAME:-}" "${BASELINE_CGROUP_NAME:-}"; do
    if [ -n "$cgroup_name" ] && [ -d "/sys/fs/cgroup/$cgroup_name" ]; then
        sudo rmdir "/sys/fs/cgroup/$cgroup_name" 2>/dev/null || true
        echo "[Done] Cgroup cleaned up: /sys/fs/cgroup/$cgroup_name"
    fi
done

python3 - "$RESULT_FILE" "$PERF_MODE" "$TEST_MEMORY" "$MEMORY_SAMPLE_INTERVAL" "$MEMORY_POLL" "$MEMORY_POLL_ENABLED" <<'PY'
import json
import sys

path, mode, test_memory, memory_interval, memory_poll, memory_poll_enabled = sys.argv[1:]
with open(path) as f:
    runs = json.load(f)
for run in runs:
    run["config"].update(
        perf_mode=mode,
        test_memory_snapshots=test_memory == "true",
        test_perf_record=mode in ("record", "both"),
        test_tracepoint=mode in ("tracepoint", "both"),
        test_memory=test_memory == "true",
        memory_interval_seconds=int(memory_interval),
        memory_poll=memory_poll,
        memory_poll_enabled=memory_poll_enabled == "true",
    )
with open(path, "w") as f:
    json.dump(runs, f, indent=4)
    f.write("\n")
PY

# Retain the latest-result path used by existing callers.
cp -f -- "$RESULT_FILE" "$LEGACY_RESULT_FILE"

echo "Benchmark completed!"
echo "对比数据 (perf_mode=$PERF_MODE) 已保存至:"
echo "-> $RESULT_FILE"
