#!/bin/bash
set -eu -o pipefail

usage() {
    echo "用法: $0 {legacy|sequential|hotspot|mixed|bimodal}"
    echo "  legacy       传统随机读负载 (验证 MGLRU, 10G)"
    echo "  sequential   顺序扫描负载 (验证 MRU/Bypass, 5G)"
    echo "  hotspot      高频热点负载 (验证 LFU/LHD, 5G, Zipf)"
    echo "  mixed        混合读写负载 (验证 ARC, 5G, 70%读)"
    echo "  bimodal      双峰扫描负载 (异构接口测试: LFU > LRU)"
    echo "  phase shift   工作集突变负载 (LRU 获胜)"
    echo "  schizophrenic   精神分裂负载 (ARC 统治全场)"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
RESULTS_PATH="$BASE_DIR/results"
FIO_DIR=$RESULTS_PATH/fio_temp
LIBCACHESIM="$BASE_DIR/../libCacheSim/_build"

# ====== 运行时环境变量 ======
ITERATIONS=1
IOENGINE="psync"

if [ ! -f "$RESULTS_PATH/fio_$1.csv" ]; then

    mkdir -p "$FIO_DIR"
    mkdir -p "$RESULTS_PATH"
    RESULT_FILE="$RESULTS_PATH/cpu_overhead_results_$1.json"
    TRACE_FILE="$RESULTS_PATH/access_trace_$1"

    # 初始化默认的资源上限
    RUNTIME=120
    CGROUP_SIZE="1G"

    # =======================================================
    # 核心：全部转为纯 JSON 驱动的拓扑配置
    # =======================================================
    case "$1" in
        legacy)
            RUNTIME=60           
            CGROUP_SIZE="5G"     
            JOB_CONFIG_JSON='[
                {
                    "name": "legacy",
                    "numjobs": 8,
                    "filename": "legacy_data.bin",
                    "size": "10g",
                    "rw": "randread",
                    "bs": "4k"
                }
            ]'
            ;;
        sequential)
            JOB_CONFIG_JSON='[
                {
                    "name": "sequential",
                    "numjobs": 1,
                    "filename": "seq_data.bin",
                    "size": "5g",
                    "rw": "read",
                    "bs": "1m"
                }
            ]'
            ;;
        hotspot)
            JOB_CONFIG_JSON='[
                {
                    "name": "hotspot",
                    "numjobs": 4,
                    "filename": "hotspot_data.bin",
                    "size": "5g",
                    "rw": "randread",
                    "bs": "4k",
                    "random_distribution": "zipf:1.2"
                }
            ]'
            ;;
        mixed)
            JOB_CONFIG_JSON='[
                {
                    "name": "mixed",
                    "numjobs": 8,
                    "filename": "mixed_data.bin",
                    "size": "5g",
                    "rw": "randrw",
                    "bs": "16k",
                    "rwmixread": 70
                }
            ]'
            ;;
        bimodal)
            JOB_CONFIG_JSON='[
                {
                    "name": "hot_core",
                    "numjobs": 4,
                    "filename": "hot_data.bin",
                    "size": "500m",
                    "rw": "randread",
                    "bs": "4k",
                    "rate_iops": 15000
                },
                {
                    "name": "cold_scan",
                    "numjobs": 1,
                    "filename": "cold_data.bin",
                    "size": "5g",
                    "rw": "read",
                    "bs": "1m"
                }
            ]'
            ;;
        phase_shift)
            JOB_CONFIG_JSON='[
                {
                    "name": "phase_1_old_hotspot",
                    "numjobs": 1,
                    "filename": "file_A.bin",
                    "size": "1g",
                    "rw": "randread",
                    "bs": "4k",
                    "runtime": 60
                },
                {
                    "name": "phase_2_new_hotspot",
                    "numjobs": 1,
                    "filename": "file_B.bin",
                    "size": "1g",
                    "rw": "randread",
                    "bs": "4k",
                    "startdelay": 60,
                    "runtime": 60
                }
            ]'
            ;;
        schizophrenic)
            JOB_CONFIG_JSON='[
                {
                    "name": "stable_core",
                    "numjobs": 1,
                    "filename": "core.bin",
                    "size": "200m",
                    "rw": "randread",
                    "bs": "4k",
                    "rate_iops": 5000
                },
                {
                    "name": "shifting_hotspot",
                    "numjobs": 1,
                    "filename": "shift.bin",
                    "size": "1g",
                    "rw": "randread",
                    "bs": "64k",
                    "rate_iops": 2000
                },
                {
                    "name": "background_scan",
                    "numjobs": 1,
                    "filename": "huge_cold.bin",
                    "size": "10g",
                    "rw": "read",
                    "bs": "1m",
                    "rate_iops": 50
                }
            ]'
            ;;
        *)
            echo "[Error] 无效的参数: $1"
            usage
            ;;
    esac

    echo "[Info] 所选负载模式: $1"

    if ! "$BASE_DIR/utils/disable-mglru.sh"; then
        echo "Failed to disable MGLRU. Please check the script."
        exit 1
    fi

    rm -f "$RESULT_FILE" "${TRACE_FILE}"* "$RESULTS_PATH/fio_$1.csv"

    # 精简后的 BASE_CMD，所有负载逻辑全权交由 --job-config 和 custom 模式接管
    BASE_CMD=(
        python3 "$BENCH_PATH/a_bench_fio.py"
        --cpu 8
        --target-dir "$FIO_DIR"
        --iterations "$ITERATIONS"
        --results-file "$RESULT_FILE"
        --cgroup-sizes "$CGROUP_SIZE"
        --runtime "$RUNTIME"
        --test-mode "custom"
        --ioengine "$IOENGINE"
        --write_iolog "$TRACE_FILE"
        --log_offset 1
        --job-config "$JOB_CONFIG_JSON"
    )

    echo "--------------------------------------------------------"
    echo "[阶段 1/1] 运行: 测试与轨迹收集"
    echo "--------------------------------------------------------"
    "${BASE_CMD[@]}" --default-only --policy-loader ""

    echo "--------------------------------------------------------"
    rm -rf "${FIO_DIR:?}"/* 2>/dev/null || true
    echo "✅ 轨迹收集完成! 正在转换数据..."

    # 统一提取 _job_ 日志
    python3 to_csv.py --pattern "${TRACE_FILE}_job_*" --out "$RESULTS_PATH/fio_$1.csv"

    $LIBCACHESIM/bin/traceConv $RESULTS_PATH/fio_$1.csv csv -t "time-col=1,obj-id-col=2,obj-size-col=3,op-col=4,delimiter=,,obj-id-is-num=1" --output-format=oracleGeneral
fi

OUTPUT_CSV="$RESULTS_PATH/results_$1.csv"
echo "policy,trace_file,cache_size,requests,miss_ratio,byte_miss_ratio,throughput" > "$OUTPUT_CSV"

for policy in fifo lru lfu arc lhd WTinyLFU ; do
    echo "Testing policy: $policy"
    result=$($LIBCACHESIM/bin/cachesim "$RESULTS_PATH/fio_$1.csv.oracleGeneral" oracleGeneral "$policy" 1gb 2>&1 | tail -n1)
    IFS=',' read -r part1 part2 part3 part4 part5 <<< "$result"
    cache_size=$(echo "$part1" | awk '{print $NF}')
    requests=$(echo "$part2" | awk '{print $1}')
    miss_ratio=$(echo "$part3" | awk '{print $NF}')
    byte_miss_ratio=$(echo "$part4" | awk '{print $NF}')
    throughput=$(echo "$part5" | awk '{print $2}')
    echo "$policy,fio_$1.csv.oracleGeneral,$cache_size,$requests,$miss_ratio,$byte_miss_ratio,$throughput" >> "$OUTPUT_CSV"
done

rm -f "$RESULTS_PATH/access_trace_$1_job"* 2>/dev/null || true
rm -f "$RESULTS_PATH/fio_$1.csv" 2>/dev/null || true

echo "All results saved to $OUTPUT_CSV"