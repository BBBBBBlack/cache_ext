#!/bin/bash
set -eu -o pipefail

AVAILABLE_WORKLOADS="legacy|sequential|hotspot|mixed|bimodal|phase_shift|schizophrenic|shifting"
AVAILABLE_POLICIES="fifo|s3fifo|lfu|lru|arc"

usage() {
    echo "用法: $0 <workload1> <workload2> <policy_a> <policy_b>"
    echo ""
    echo "  workload: $AVAILABLE_WORKLOADS"
    echo "  policy:   $AVAILABLE_POLICIES"
    echo ""
    echo "示例:"
    echo "  $0 hotspot sequential lfu fifo"
    echo "  $0 bimodal sequential lfu fifo"
    echo "  $0 schizophrenic legacy lfu fifo"
    echo ""
    echo "对比 4 组:"
    echo "  1) Baseline (无 cache_ext)"
    echo "  2) Dispatcher + 静态 policy_a (全程)"
    echo "  3) Dispatcher + 静态 policy_b (全程)"
    echo "  4) Dispatcher + 动态切换 policy_a → policy_b"
    exit 1
}

[[ $# -ne 4 ]] && usage

if ! uname -r | grep -q "cache-ext"; then
    echo "This script requires the cache_ext kernel."
    exit 1
fi

WORKLOAD1="$1"
WORKLOAD2="$2"
POLICY_A="$3"
POLICY_B="$4"

SCRIPT_PATH=$(realpath "$0")
BASE_DIR=$(realpath "$(dirname "$SCRIPT_PATH")/../../")
BENCH_PATH="$BASE_DIR/bench"
RESULTS_PATH="$BASE_DIR/results"
FIO_DIR="$RESULTS_PATH/fio_temp"
POLICY_PATH="$BASE_DIR/policies"
LOG_DIR="$(dirname "$SCRIPT_PATH")"

ITERATIONS=1
IOENGINE="psync"
CGROUP_TEST_PATH="/sys/fs/cgroup/cache_ext_test"
PHASE_DURATION=90
TOTAL_RUNTIME=$((PHASE_DURATION * 2))
CGROUP_SIZE="1G"

# 输出一个 workload 的 fio job JSON 对象（可能多个，逗号分隔）
# 用法: workload_jobs <workload_name> <phase: 1|2>
workload_jobs() {
    local wl="$1"
    local phase="$2"
    local rt="$PHASE_DURATION"
    local sd=""
    [ "$phase" -eq 2 ] && sd=", \"startdelay\": $PHASE_DURATION"

    case "$wl" in
        legacy)
echo "{ \"name\": \"p${phase}_legacy\", \"numjobs\": 8, \"filename\": \"legacy_data.bin\", \"size\": \"10g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${rt}${sd} }"
            ;;
        sequential)
echo "{ \"name\": \"p${phase}_sequential\", \"numjobs\": 1, \"filename\": \"seq_data.bin\", \"size\": \"5g\", \"rw\": \"read\", \"bs\": \"1m\", \"runtime\": ${rt}${sd} }"
            ;;
        hotspot)
echo "{ \"name\": \"p${phase}_hotspot\", \"numjobs\": 4, \"filename\": \"hotspot_data.bin\", \"size\": \"5g\", \"rw\": \"randread\", \"bs\": \"4k\", \"random_distribution\": \"zipf:1.2\", \"runtime\": ${rt}${sd} }"
            ;;
        mixed)
echo "{ \"name\": \"p${phase}_mixed\", \"numjobs\": 8, \"filename\": \"mixed_data.bin\", \"size\": \"5g\", \"rw\": \"randrw\", \"bs\": \"16k\", \"rwmixread\": 70, \"runtime\": ${rt}${sd} }"
            ;;
        bimodal)
echo "{ \"name\": \"p${phase}_hot_core\", \"numjobs\": 4, \"filename\": \"hot_data.bin\", \"size\": \"500m\", \"rw\": \"randread\", \"bs\": \"4k\", \"rate_iops\": 15000, \"runtime\": ${rt}${sd} },"
echo "{ \"name\": \"p${phase}_cold_scan\", \"numjobs\": 1, \"filename\": \"cold_data.bin\", \"size\": \"5g\", \"rw\": \"read\", \"bs\": \"1m\", \"runtime\": ${rt}${sd} }"
            ;;
        phase_shift)
            local half=$((rt / 2))
            if [ "$phase" -eq 2 ]; then
echo "{ \"name\": \"p${phase}_old_hotspot\", \"numjobs\": 1, \"filename\": \"file_A.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${half}, \"startdelay\": ${PHASE_DURATION} },"
echo "{ \"name\": \"p${phase}_new_hotspot\", \"numjobs\": 1, \"filename\": \"file_B.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${half}, \"startdelay\": $((PHASE_DURATION + half)) }"
            else
echo "{ \"name\": \"p${phase}_old_hotspot\", \"numjobs\": 1, \"filename\": \"file_A.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${half} },"
echo "{ \"name\": \"p${phase}_new_hotspot\", \"numjobs\": 1, \"filename\": \"file_B.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${half}, \"startdelay\": ${half} }"
            fi
            ;;
        schizophrenic)
echo "{ \"name\": \"p${phase}_stable_core\", \"numjobs\": 1, \"filename\": \"core.bin\", \"size\": \"200m\", \"rw\": \"randread\", \"bs\": \"4k\", \"rate_iops\": 5000, \"runtime\": ${rt}${sd} },"
echo "{ \"name\": \"p${phase}_shifting_hotspot\", \"numjobs\": 1, \"filename\": \"shift.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"64k\", \"rate_iops\": 2000, \"runtime\": ${rt}${sd} },"
echo "{ \"name\": \"p${phase}_background_scan\", \"numjobs\": 1, \"filename\": \"huge_cold.bin\", \"size\": \"10g\", \"rw\": \"read\", \"bs\": \"1m\", \"rate_iops\": 50, \"runtime\": ${rt}${sd} }"
            ;;
        shifting)
            local quarter=$((rt / 4))
            local base_sd=0
            [ "$phase" -eq 2 ] && base_sd=$PHASE_DURATION
echo "{ \"name\": \"p${phase}_region_a\", \"numjobs\": 4, \"filename\": \"region_a.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${quarter}, \"startdelay\": ${base_sd} },"
echo "{ \"name\": \"p${phase}_region_b\", \"numjobs\": 4, \"filename\": \"region_b.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${quarter}, \"startdelay\": $((base_sd + quarter)) },"
echo "{ \"name\": \"p${phase}_region_c\", \"numjobs\": 4, \"filename\": \"region_c.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${quarter}, \"startdelay\": $((base_sd + quarter * 2)) },"
echo "{ \"name\": \"p${phase}_region_d\", \"numjobs\": 4, \"filename\": \"region_d.bin\", \"size\": \"1g\", \"rw\": \"randread\", \"bs\": \"4k\", \"runtime\": ${quarter}, \"startdelay\": $((base_sd + quarter * 3)) }"
            ;;
        *)
            echo "[Error] Unknown workload: $wl" >&2
            usage
            ;;
    esac
}

validate_policy() {
    case "$1" in
        fifo|s3fifo|lfu|lru|arc) ;;
        *)
            echo "[Error] 无效的 policy: $1" >&2
            usage
            ;;
    esac
}

validate_policy "$POLICY_A"
validate_policy "$POLICY_B"

# 验证 workload 合法性（顺便触发 case 中的 * 报错）
workload_jobs "$WORKLOAD1" 1 > /dev/null
workload_jobs "$WORKLOAD2" 2 > /dev/null

JOB_CONFIG_JSON="[ $(workload_jobs "$WORKLOAD1" 1), $(workload_jobs "$WORKLOAD2" 2) ]"

SCENARIO_TAG="${WORKLOAD1}_to_${WORKLOAD2}"

echo "========================================================"
echo " Migration Benchmark"
echo " Workload: $WORKLOAD1 (${PHASE_DURATION}s) → $WORKLOAD2 (${PHASE_DURATION}s)"
echo " Policy:   $POLICY_A → $POLICY_B"
echo "========================================================"

mkdir -p "$FIO_DIR" "$RESULTS_PATH"

if ! "$BASE_DIR/utils/disable-mglru.sh"; then
    echo "Failed to disable MGLRU."
    exit 1
fi

RESULT_BASELINE="$RESULTS_PATH/migration_${SCENARIO_TAG}_1_baseline.json"
RESULT_STATIC_A="$RESULTS_PATH/migration_${SCENARIO_TAG}_2_static_${POLICY_A}.json"
RESULT_STATIC_B="$RESULTS_PATH/migration_${SCENARIO_TAG}_3_static_${POLICY_B}.json"
RESULT_DYNAMIC="$RESULTS_PATH/migration_${SCENARIO_TAG}_4_dynamic_${POLICY_A}_to_${POLICY_B}.json"
rm -f "$RESULT_BASELINE" "$RESULT_STATIC_A" "$RESULT_STATIC_B" "$RESULT_DYNAMIC"

TS_LOG_DIR="$RESULTS_PATH/migration_${SCENARIO_TAG}_logs"
mkdir -p "$TS_LOG_DIR"
LOG_BASELINE="$TS_LOG_DIR/1_baseline"
LOG_STATIC_A="$TS_LOG_DIR/2_static_${POLICY_A}"
LOG_STATIC_B="$TS_LOG_DIR/3_static_${POLICY_B}"
LOG_DYNAMIC="$TS_LOG_DIR/4_dynamic_${POLICY_A}_to_${POLICY_B}"

run_bench() {
    local rf="$1"
    shift
    python3 "$BENCH_PATH/a_bench_fio.py" \
        --cpu 8 \
        --target-dir "$FIO_DIR" \
        --iterations "$ITERATIONS" \
        --results-file "$rf" \
        --cgroup-sizes "$CGROUP_SIZE" \
        --runtime "$TOTAL_RUNTIME" \
        --test-mode "custom" \
        --ioengine "$IOENGINE" \
        --job-config "$JOB_CONFIG_JSON" \
        "$@"
}

cleanup_dispatcher() {
    sudo killall -9 a_user_loader.out 2>/dev/null || true
    sudo killall -9 a_dispatcher.out 2>/dev/null || true
    wait 2>/dev/null || true
    sleep 1
    if [ -f /sys/fs/bpf/dispatcher_registry ]; then
        sudo rm -f /sys/fs/bpf/dispatcher_registry
    fi
    if [ -d /sys/fs/bpf/cache_ext ]; then
        sudo rm -rf /sys/fs/bpf/cache_ext
    fi
    if [ -d "$CGROUP_TEST_PATH" ]; then
        sudo rmdir "$CGROUP_TEST_PATH" 2>/dev/null || true
    fi
    rm -rf "${FIO_DIR:?}"/* 2>/dev/null || true
}

start_dispatcher() {
    sudo mkdir -p "$CGROUP_TEST_PATH"
    sudo "$POLICY_PATH/a_dispatcher.out" \
        -w "$FIO_DIR" -c "$CGROUP_TEST_PATH" \
        > "$LOG_DIR/dispatcher_migration.log" 2>&1 &
    sleep 2
}

run_static_policy() {
    local policy="$1"
    local rf="$2"
    local log_prefix="$3"
    start_dispatcher
    sudo "$POLICY_PATH/a_user_loader.out" \
        -c "$CGROUP_TEST_PATH" -o "$policy" \
        > "$LOG_DIR/loader_migration.log" 2>"$LOG_DIR/loader_migration_err.log" &
    sleep 2
    run_bench "$rf" --policy-loader "" --bw-log "$log_prefix"
    cleanup_dispatcher
}

run_dynamic_switch() {
    local old_pol="$1"
    local new_pol="$2"
    local delay="$3"
    local rf="$4"
    local log_prefix="$5"

    local trigger_fifo
    trigger_fifo=$(mktemp -u /tmp/migration_trigger.XXXXXX)
    mkfifo "$trigger_fifo"

    start_dispatcher

    # 用读写模式打开 FIFO，使 loader 的 < fifo 不会阻塞在 open() 上
    # （O_RDWR 同时满足读端和写端，不会阻塞）
    exec 3<>"$trigger_fifo"

    sudo "$POLICY_PATH/a_user_loader.out" \
        -c "$CGROUP_TEST_PATH" -o "$old_pol" -n "$new_pol" \
        < "$trigger_fifo" \
        > "$LOG_DIR/loader_migration.log" 2>"$LOG_DIR/loader_migration_err.log" &
    sleep 2

    # 等 fio 进程出现后再开始倒计时，确保 delay 对齐 fio 实际启动时刻
    (
        while ! pgrep -x fio > /dev/null 2>&1; do sleep 0.2; done
        sleep "$delay"
        echo >&3
        exec 3>&-
    ) &
    local trigger_pid=$!

    run_bench "$rf" --policy-loader "" --bw-log "$log_prefix"

    wait "$trigger_pid" 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    rm -f "$trigger_fifo"
    cleanup_dispatcher
}

trap cleanup_dispatcher EXIT

# ====================================================================
# [1/4] Baseline
# ====================================================================
echo ""
echo "--------------------------------------------------------"
echo "[1/4] Baseline (无 cache_ext)"
echo "--------------------------------------------------------"
run_bench "$RESULT_BASELINE" --default-only --policy-loader "" --bw-log "$LOG_BASELINE"
rm -rf "${FIO_DIR:?}"/* 2>/dev/null || true

# ====================================================================
# [2/4] 静态 Policy A
# ====================================================================
echo ""
echo "--------------------------------------------------------"
echo "[2/4] Dispatcher + 静态 $POLICY_A (全程 ${TOTAL_RUNTIME}s)"
echo "--------------------------------------------------------"
run_static_policy "$POLICY_A" "$RESULT_STATIC_A" "$LOG_STATIC_A"

# ====================================================================
# [3/4] 静态 Policy B
# ====================================================================
echo ""
echo "--------------------------------------------------------"
echo "[3/4] Dispatcher + 静态 $POLICY_B (全程 ${TOTAL_RUNTIME}s)"
echo "--------------------------------------------------------"
run_static_policy "$POLICY_B" "$RESULT_STATIC_B" "$LOG_STATIC_B"

# ====================================================================
# [4/4] 动态切换 A → B
# ====================================================================
SWITCH_DELAY=$PHASE_DURATION
echo ""
echo "--------------------------------------------------------"
echo "[4/4] Dispatcher + 动态切换 $POLICY_A → $POLICY_B (${PHASE_DURATION}s 处切换)"
echo "--------------------------------------------------------"
run_dynamic_switch "$POLICY_A" "$POLICY_B" "$SWITCH_DELAY" "$RESULT_DYNAMIC" "$LOG_DYNAMIC"

# ====================================================================
# 收尾
# ====================================================================
echo ""
echo "========================================================"
echo "Benchmark 完成! 4 组对比数据:"
echo "  1) Baseline:           $RESULT_BASELINE"
echo "  2) 静态 $POLICY_A:      $RESULT_STATIC_A"
echo "  3) 静态 $POLICY_B:      $RESULT_STATIC_B"
echo "  4) 动态 $POLICY_A→$POLICY_B: $RESULT_DYNAMIC"
echo ""
echo "时序日志目录: $TS_LOG_DIR"
echo "  每组包含 *_bw.*.log / *_iops.*.log / *_lat.*.log"
echo "========================================================"
