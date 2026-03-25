#!/bin/bash
set -eu -o pipefail

# 1. 检查内核
if ! uname -r | grep -q "cache-ext"; then
    echo "Error: Not running on cache_ext kernel."
    exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
POLICY_PATH="$BASE_DIR/policies"
# FILES_PATH=$(realpath "$BASE_DIR/../ghost-kernel")
FILES_PATH=$(realpath "$BASE_DIR/linux/arch/x86/boot/compressed/")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# 2. 必须禁用 MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
    echo "Failed to disable MGLRU."
    exit 1
fi

# 3. 清理旧结果 (重要！否则会 Skipping)
rm -f "$RESULTS_PATH/filesearch_results_a_policy.json"

echo "Running Cache Ext Policy ONLY..."

# 4. 运行 Python 脚本
python3 "$BENCH_PATH/a_filesearch.py" \
    --cpu 8 \
    --policy-loader "$POLICY_PATH/a_dispatcher.out" \
    --results-file "$RESULTS_PATH/filesearch_results_a_policy.json" \
    --data-dir "$FILES_PATH" \
    --iterations "$ITERATIONS"

echo "Done."
