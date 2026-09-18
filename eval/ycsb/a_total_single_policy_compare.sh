#!/bin/bash
set -eu -o pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")

POLICY="${1:-lfu}"
CGROUP_SIZE="${2:-1G}"

BENCHMARKS=(ycsb_a ycsb_b ycsb_c ycsb_d ycsb_e ycsb_f)
# BENCHMARKS=(ycsb_a)

for bench in "${BENCHMARKS[@]}"; do
    echo "========================================================"
    echo " Running: $bench  policy=$POLICY  cgroup=$CGROUP_SIZE"
    echo "========================================================"
    # "$SCRIPT_DIR/a_single_policy_compare.sh" "$bench" "$POLICY" "2G" test_memory=false test_perf=false
    "$SCRIPT_DIR/a_single_policy_compare.sh" "$bench" "$POLICY" "$CGROUP_SIZE" test_memory=false test_perf=false
    echo ""
    sleep 3
done

echo "All benchmarks completed."
