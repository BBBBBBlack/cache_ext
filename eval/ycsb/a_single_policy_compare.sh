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
    echo "  test_memory:  默认 false；true 时按 memory_interval 采样 baseline_test/cache_ext_test 的 memory.stat、memory.pressure 和 io.stat"
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
TEST_PERF=false
DISABLE_READAHEAD=false
MEMORY_SAMPLE_INTERVAL=5
RUNTIME_SECONDS=240
WARMUP_RUNTIME_SECONDS=45
BASELINE_CGROUP_NAME="baseline_test"
CACHE_EXT_CGROUP_NAME="cache_ext_test"

for arg in "${@:3}"; do
    case "$arg" in
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
echo "[Info] memory/io 采样间隔: ${MEMORY_SAMPLE_INTERVAL}s"
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

    if [ "$TEST_MEMORY" != "true" ]; then
        return 0
    fi

    echo "[Info] 启动 memory/io/pressure 采样: stage=$stage cgroup=$cgroup_name interval=${MEMORY_SAMPLE_INTERVAL}s"
    echo "[Info] memory/io/pressure 日志: $log_file"

    (
        echo "# stage=$stage"
        echo "# cgroup=$cgroup_name"
        echo "# cgroup_path=$cgroup_path"
        echo "# interval_seconds=$MEMORY_SAMPLE_INTERVAL"
        echo "# fields: timestamp memory.current selected memory.stat memory.pressure io.stat"
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
        echo "# note: add_to_page_cache counts page-cache insertions/refills; prefetch counts readahead insertions; demand_miss_estimate ~= add_to_page_cache - prefetch"

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

append_validation_summary() {
    if [ "$TEST_MEMORY" != "true" ] || [ "$TEST_PERF" != "true" ]; then
        return 0
    fi

    local validation_log="$RESULTS_PATH/ycsb_spc_${POLICY_NAME}_${BENCHMARK_TAG}_${CGROUP_SIZE_TAG}_validation.log"

    python3 - "$RESULT_FILE" "$RESULTS_PATH" "$POLICY_NAME" "$BENCHMARK_TAG" "$CGROUP_SIZE_TAG" "$RUNTIME_SECONDS" "$validation_log" <<'PY'
import json
import os
import re
import sys

result_file, results_path, policy, benchmark_tag, cgroup_tag, runtime_s, validation_log = sys.argv[1:]
runtime_s = float(runtime_s)

stages = ["baseline", f"direct_{policy}", f"dispatcher_{policy}"]

def parse_mem_log(path):
    blocks = []
    block = None

    if not os.path.exists(path):
        return None

    with open(path, errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("timestamp "):
                if block is not None:
                    blocks.append(block)
                block = {"io": {}, "mem": {}}
                continue
            if block is None:
                continue
            if line.startswith("memory.current "):
                parts = line.split()
                if len(parts) == 2 and parts[1].isdigit():
                    block["mem"]["memory.current"] = int(parts[1])
                continue
            if line.startswith("io.stat "):
                parts = line.split()
                if len(parts) < 3:
                    continue
                dev = parts[1]
                entry = {}
                for p in parts[2:]:
                    if "=" not in p:
                        continue
                    k, v = p.split("=", 1)
                    if v.isdigit():
                        entry[k] = int(v)
                if entry:
                    block["io"][dev] = entry
                continue
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                block["mem"][parts[0]] = int(parts[1])

    if block is not None:
        blocks.append(block)

    blocks = [b for b in blocks if "memory.current" in b["mem"]]
    if len(blocks) < 2:
        return None

    first, last = blocks[0], blocks[-1]
    io_blocks = [b for b in blocks if b.get("io")]
    first_io = io_blocks[0] if io_blocks else {}
    last_io = io_blocks[-1] if io_blocks else {}

    def io_delta_for_dev(dev, key):
        first_val = first_io.get("io", {}).get(dev, {}).get(key, 0)
        last_val = last_io.get("io", {}).get(dev, {}).get(key, 0)
        return max(0, last_val - first_val)

    common_devs = set(first_io.get("io", {})) & set(last_io.get("io", {}))
    numeric_devs = [d for d in common_devs if re.fullmatch(r"[0-9]+:[0-9]+", d)]
    non_dm_numeric_devs = [d for d in numeric_devs if not d.startswith("253:")]
    candidate_devs = non_dm_numeric_devs or numeric_devs or sorted(common_devs)
    io_device = None
    if candidate_devs:
        io_device = max(
            candidate_devs,
            key=lambda d: (
                io_delta_for_dev(d, "rbytes") + io_delta_for_dev(d, "wbytes"),
                io_delta_for_dev(d, "rios") + io_delta_for_dev(d, "wios"),
                d,
            ),
        )

    return {
        "samples": len(blocks),
        "io_samples": len(io_blocks),
        "io_device": io_device or "unavailable",
        "rbytes_delta": io_delta_for_dev(io_device, "rbytes") if io_device else 0,
        "wbytes_delta": io_delta_for_dev(io_device, "wbytes") if io_device else 0,
        "rios_delta": io_delta_for_dev(io_device, "rios") if io_device else 0,
        "wios_delta": io_delta_for_dev(io_device, "wios") if io_device else 0,
        "pgscan_delta": max(0, last["mem"].get("pgscan", 0) - first["mem"].get("pgscan", 0)),
        "pgsteal_delta": max(0, last["mem"].get("pgsteal", 0) - first["mem"].get("pgsteal", 0)),
        "memory_current_max": max(b["mem"].get("memory.current", 0) for b in blocks),
        "file_dirty_max": max(b["mem"].get("file_dirty", 0) for b in blocks),
        "file_writeback_max": max(b["mem"].get("file_writeback", 0) for b in blocks),
    }

def parse_pcache_log(path):
    out = {
        "add_to_page_cache": None,
        "readahead_prefetch": None,
        "demand_miss_estimate": None,
        "perf_stat_ok": False,
    }
    if not os.path.exists(path):
        return out

    with open(path, errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if "not supported" in line or "unknown tracepoint" in line or "event syntax error" in line:
                out["error"] = line
            parts = line.split(",")
            if len(parts) < 3:
                continue
            count = parts[0].strip().replace(",", "")
            event = parts[2].strip()
            if not re.fullmatch(r"[0-9]+", count):
                continue
            val = int(count)
            if event.endswith("mm_filemap_add_to_page_cache"):
                out["add_to_page_cache"] = val
                out["perf_stat_ok"] = True
            elif event.endswith("mm_filemap_add_to_page_cache_prefetch"):
                out["readahead_prefetch"] = val
                out["perf_stat_ok"] = True

    if out["add_to_page_cache"] is not None and out["readahead_prefetch"] is not None:
        out["demand_miss_estimate"] = max(0, out["add_to_page_cache"] - out["readahead_prefetch"])
    return out

def fmt_bytes(v):
    return f"{v / (1024 ** 3):.3f} GiB"

try:
    with open(result_file) as f:
        results = json.load(f)
except FileNotFoundError:
    results = []

rows = []
for idx, stage in enumerate(stages):
    mem_log = os.path.join(results_path, f"ycsb_spc_{policy}_{benchmark_tag}_{cgroup_tag}_mem_{stage}.log")
    pcache_log = os.path.join(results_path, f"ycsb_spc_{policy}_{benchmark_tag}_{cgroup_tag}_pcache_{stage}.log")
    mem = parse_mem_log(mem_log)
    pcache = parse_pcache_log(pcache_log)
    bench = results[idx]["results"] if idx < len(results) else {}
    throughput = float(bench.get("throughput_avg", 0) or 0)
    ops = throughput * runtime_s

    rows.append({
        "stage": stage,
        "throughput_ops_s": throughput,
        "estimated_ops": ops,
        "mem": mem,
        "pcache": pcache,
    })

with open(validation_log, "w") as f:
    f.write("# cache_ext YCSB validation summary\n")
    f.write(f"# result_file={result_file}\n")
    f.write(f"# runtime_seconds={runtime_s:.0f}\n")
    f.write("# caveat: io.stat may include stacked block devices; use same-method relative comparison unless device is filtered.\n\n")
    for row in rows:
        stage = row["stage"]
        ops = row["estimated_ops"]
        mem = row["mem"]
        pc = row["pcache"]
        f.write(f"[{stage}]\n")
        f.write(f"throughput_ops_s={row['throughput_ops_s']:.2f}\n")
        f.write(f"estimated_ops={ops:.0f}\n")
        if mem and ops > 0:
            f.write(f"io_device={mem['io_device']}\n")
            f.write(f"read_io={fmt_bytes(mem['rbytes_delta'])}\n")
            f.write(f"write_io={fmt_bytes(mem['wbytes_delta'])}\n")
            f.write(f"read_bytes_per_op={mem['rbytes_delta'] / ops:.3f}\n")
            f.write(f"write_bytes_per_op={mem['wbytes_delta'] / ops:.3f}\n")
            f.write(f"read_ios_per_kop={mem['rios_delta'] / ops * 1000:.6f}\n")
            f.write(f"write_ios_per_kop={mem['wios_delta'] / ops * 1000:.6f}\n")
            f.write(f"pgscan_per_kop={mem['pgscan_delta'] / ops * 1000:.6f}\n")
            f.write(f"pgsteal_per_kop={mem['pgsteal_delta'] / ops * 1000:.6f}\n")
            f.write(f"memory_current_max={mem['memory_current_max']}\n")
            f.write(f"file_dirty_max={mem['file_dirty_max']}\n")
            f.write(f"file_writeback_max={mem['file_writeback_max']}\n")
        else:
            f.write("normalized_io=unavailable\n")
        for key in ["add_to_page_cache", "readahead_prefetch", "demand_miss_estimate"]:
            val = pc.get(key)
            f.write(f"{key}={val if val is not None else 'unavailable'}\n")
            if val is not None and ops > 0:
                f.write(f"{key}_per_kop={val / ops * 1000:.6f}\n")
        if pc.get("error"):
            f.write(f"pcache_error={pc['error']}\n")
        f.write("\n")

print(f"[Done] validation summary written: {validation_log}")
PY
}

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
"${BASE_CMD[@]}" --default-only --policy-loader ""
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
"${BASE_CMD[@]}" --policy-loader "$POLICY_PATH/cache_ext_${POLICY_NAME}.out"
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
"${BASE_CMD[@]}" --policy-loader ""
stop_perf_monitor
stop_pcache_monitor
stop_memory_monitor

append_validation_summary

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
