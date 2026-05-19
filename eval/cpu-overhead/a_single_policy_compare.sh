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

if [ $# -ne 2 ]; then
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
FIO_DIR=$RESULTS_PATH/fio_temp
POLICY_PATH="$BASE_DIR/policies"


# ====== 运行时环境变量 ======
ITERATIONS=1
IOENGINE="psync"


mkdir -p "$FIO_DIR"
mkdir -p "$RESULTS_PATH"
WORKLOAD_MODE="$1"
POLICY_NAME="$2"
RESULT_FILE="$RESULTS_PATH/cpu_overhead_results_$1.json"

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

case "$POLICY_NAME" in
    fifo|lru|lfu|arc|lhd|s3fifo)
    ;;
    *)
    echo "[Error] 无效的策略: $POLICY_NAME"
    usage
    ;;
esac

echo "[Info] 所选负载模式: $WORKLOAD_MODE"
echo "[Info] 所选 cache_ext 策略: $POLICY_NAME"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# 清除旧数据，确保每次运行都是全新的三组对比
rm -f "$RESULT_FILE"

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
    --job-config "$JOB_CONFIG_JSON"
)

# ====================================================================
# 阶段 1/3：运行原生 Linux 基线测试 (Baseline)
# ====================================================================
echo "--------------------------------------------------------"
echo "[阶段 1/3] 运行: 原生 Linux 默认页面缓存 (Baseline)"
echo "--------------------------------------------------------"
"${BASE_CMD[@]}" --default-only --policy-loader ""


# ====================================================================
# 阶段 2/3：运行 cache_ext 独立策略测试
# ====================================================================
echo "--------------------------------------------------------"
echo "[阶段 2/3] 运行: cache_ext 独立加载 $POLICY_NAME 策略"
echo "--------------------------------------------------------"
# 直接提供二进制路径，Python 会自动拉起它执行
"${BASE_CMD[@]}" --policy-loader "$POLICY_PATH/cache_ext_${POLICY_NAME}.out"


# ====================================================================
# 阶段 3/3：运行 cache_ext Dispatcher + 策略测试
# ====================================================================
echo "--------------------------------------------------------"
echo "[阶段 3/3] 运行: cache_ext Dispatcher 热插拔路由 + $POLICY_NAME"
echo "--------------------------------------------------------"
CGROUP_TEST_PATH="/sys/fs/cgroup/cache_ext_test"
sudo mkdir -p "$CGROUP_TEST_PATH"

# 3.1 启动 Dispatcher 守护进程 (后台执行)
echo "[Info] 启动后台 Dispatcher..."
sudo "$POLICY_PATH/a_dispatcher.out" -w "$FIO_DIR" -c "$CGROUP_TEST_PATH" > dispatcher_bench.log 2>&1 &
DISPATCHER_PID=$!
sleep 2 # 等待 Dispatcher 挂载 eBPF 探针并创建注册表

# 3.2 启动 User Loader 并挂载 FIFO 策略 (单策略模式常驻后台)
echo "[Info] 启动后台 User Loader (正在将 $POLICY_NAME 挂载至 Dispatcher 槽位)..."
sudo "$POLICY_PATH/a_user_loader.out" -c "$CGROUP_TEST_PATH" -o "$POLICY_NAME" > loader_bench.log 2>&1 &
LOADER_PID=$!
sleep 2 # 等待 Loader 就绪

# 3.3 触发 Fio 压测 
# 此处传入空的 policy-loader 确保 Python 不会自己去挂载新策略，而是让 fio 流量流入后台准备好的 Dispatcher
echo "[Info] 正在发送 FIO 压测流量..."
"${BASE_CMD[@]}" --policy-loader ""

# 3.4 清理后台架构进程
echo "[Info] 压测结束，清理 Dispatcher 和 Loader 后台进程..."
sudo killall -9 a_user_loader.out 2>/dev/null || true
sudo killall -9 a_dispatcher.out 2>/dev/null || true
sleep 1

# ====================================================================
# 收尾工作
# ====================================================================
echo "--------------------------------------------------------"
echo "[Info] 测试执行完毕，清理临时文件..."
# wait $! 2>/dev/null

rm -rf "${FIO_DIR:?}"/* 2>/dev/null || true


if [ -d "/sys/fs/bpf/cache_ext" ]; then
    sudo rm -rf /sys/fs/bpf/cache_ext
    echo "[Done] eBPF maps unpinned."
fi
if [ -d "$CGROUP_TEST_PATH" ]; then
    sudo rmdir "$CGROUP_TEST_PATH"
    echo "[Done] Cgroup cleaned up."
fi

echo "✅ Benchmark completed!" 
echo "3组对比数据 (Baseline / $POLICY_NAME / Dispatcher+$POLICY_NAME) 已完美合并并保存至:"
echo "-> $RESULT_FILE"