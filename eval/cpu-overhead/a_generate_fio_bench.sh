#!/usr/bin/env bash
set -euo pipefail

# Generate warmup-aware, pressure-scaled fio job arrays for the cache_ext
# a_* policies. This script only writes benchmark definitions; it does not run
# fio, load policies, change cgroups, or clean experiment data.

SUPPORTED_POLICIES=(fifo s3fifo lfu lru arc)
SUPPORTED_PRESSURES=(low medium high)

SCRIPT_PATH=$(realpath "$0")
BASE_DIR=$(realpath "$(dirname "$SCRIPT_PATH")/../..")

TARGET_POLICY="all"
PRESSURE_FILTER="all"
OUTPUT_DIR="$BASE_DIR/results/generated-fio-benches"
MEASUREMENT_SECONDS=120
CGROUP_SIZE="320M"
IOENGINE="psync"

FIFO_WARMUP_SECONDS=45
S3FIFO_WARMUP_SECONDS=60
LFU_WARMUP_SECONDS=120
LRU_WARMUP_SECONDS=60
ARC_WARMUP_SECONDS=90

usage() {
    cat <<EOF
Usage: $0 [all|fifo|s3fifo|lfu|lru|arc] [options]

Generate fio custom-job JSON for cache_ext policy-oriented benchmarks.
The selected policy chooses which benchmark family to emit; it does not run
that policy.

Options:
  --output-dir DIR          Output directory (default: $OUTPUT_DIR)
  --pressure LEVEL          all, low, medium, or high (default: $PRESSURE_FILTER)
  --runtime SEC             Steady-state measurement runtime
                            alias: --measurement-seconds (default: $MEASUREMENT_SECONDS)
  --cgroup-size SIZE        Intended memory.max value recorded in manifest
                            (default: $CGROUP_SIZE)
  --ioengine NAME           fio ioengine recorded in manifest (default: $IOENGINE)
  --warmup-seconds SEC      Override warmup for every policy
  --fifo-warmup-seconds SEC     FIFO warmup/ramp_time (default: $FIFO_WARMUP_SECONDS)
  --s3fifo-warmup-seconds SEC   S3FIFO warmup/ramp_time (default: $S3FIFO_WARMUP_SECONDS)
  --lfu-warmup-seconds SEC      LFU warmup/ramp_time (default: $LFU_WARMUP_SECONDS)
  --lru-warmup-seconds SEC      LRU warmup/ramp_time (default: $LRU_WARMUP_SECONDS)
  --arc-warmup-seconds SEC      ARC warmup/ramp_time (default: $ARC_WARMUP_SECONDS)
  -h, --help                Show this help

Generated benchmark families:
  fifo    cold_streams         6 independent cold random streams, high ~= 6.6k IOPS
  s3fifo  hot_cold_mix         hot Zipf core + light cold pollution, high ~= 10k IOPS
  lfu     frequency_retention  hot frequency set + light noise, high ~= 10k IOPS
  lru     recent_window        recent-window locality + light perturbation, high ~= 8k IOPS
  arc     mixed_locality       frequent + recent + cold mix, high ~= 10k IOPS

Pressure levels are implemented by scaling per-job rate_iops:
  low=0.30x, medium=0.60x, high=1.00x

All generated jobs use:
  bs=4k, rw=randread, direct=0 in a_bench_fio.py, ramp_time warmup,
  no sequential scan, and steady_* job names.

Each job JSON also contains metadata fields ignored by fio but consumed by
the runner/plotter:
  group, target_policy, pressure, intent

The manifest records primary/polluter group intent so the report can judge
the policy-specific success metric without letting polluter/noise jobs dominate
the overall tail latency.

If generated file sizes changed after an earlier run, pass --reset-fio-dir to
a_run_fio_bench.sh once so stale fio data files do not fail size validation.
EOF
}

die() {
    echo "[Error] $*" >&2
    exit 1
}

is_supported_policy() {
    case "$1" in
        fifo|s3fifo|lfu|lru|arc) return 0 ;;
        *) return 1 ;;
    esac
}

is_supported_pressure() {
    case "$1" in
        all|low|medium|high) return 0 ;;
        *) return 1 ;;
    esac
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

profile_for_policy() {
    case "$1" in
        fifo) echo "cold_streams" ;;
        s3fifo) echo "hot_cold_mix" ;;
        lfu) echo "frequency_retention" ;;
        lru) echo "recent_window" ;;
        arc) echo "mixed_locality" ;;
        *) die "no workload profile for policy '$1'" ;;
    esac
}

policy_warmup_seconds() {
    case "$1" in
        fifo) echo "$FIFO_WARMUP_SECONDS" ;;
        s3fifo) echo "$S3FIFO_WARMUP_SECONDS" ;;
        lfu) echo "$LFU_WARMUP_SECONDS" ;;
        lru) echo "$LRU_WARMUP_SECONDS" ;;
        arc) echo "$ARC_WARMUP_SECONDS" ;;
        *) die "no warmup default for policy '$1'" ;;
    esac
}

pressure_pct() {
    case "$1" in
        low) echo 30 ;;
        medium) echo 60 ;;
        high) echo 100 ;;
        *) die "unsupported pressure '$1'" ;;
    esac
}

scale_rate() {
    local high_rate="$1"
    local pressure="$2"
    local pct
    pct=$(pressure_pct "$pressure")
    echo $(((high_rate * pct + 50) / 100))
}

target_was_set=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            [[ $# -ge 2 ]] || die "--output-dir requires a value"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --pressure)
            [[ $# -ge 2 ]] || die "--pressure requires a value"
            PRESSURE_FILTER="$2"
            shift 2
            ;;
        --runtime|--measurement-seconds)
            [[ $# -ge 2 ]] || die "--runtime/--measurement-seconds requires a value"
            MEASUREMENT_SECONDS="$2"
            shift 2
            ;;
        --cgroup-size)
            [[ $# -ge 2 ]] || die "--cgroup-size requires a value"
            CGROUP_SIZE="$2"
            shift 2
            ;;
        --ioengine)
            [[ $# -ge 2 ]] || die "--ioengine requires a value"
            IOENGINE="$2"
            shift 2
            ;;
        --warmup-seconds)
            [[ $# -ge 2 ]] || die "--warmup-seconds requires a value"
            FIFO_WARMUP_SECONDS="$2"
            S3FIFO_WARMUP_SECONDS="$2"
            LFU_WARMUP_SECONDS="$2"
            LRU_WARMUP_SECONDS="$2"
            ARC_WARMUP_SECONDS="$2"
            shift 2
            ;;
        --fifo-warmup-seconds)
            [[ $# -ge 2 ]] || die "--fifo-warmup-seconds requires a value"
            FIFO_WARMUP_SECONDS="$2"
            shift 2
            ;;
        --s3fifo-warmup-seconds)
            [[ $# -ge 2 ]] || die "--s3fifo-warmup-seconds requires a value"
            S3FIFO_WARMUP_SECONDS="$2"
            shift 2
            ;;
        --lfu-warmup-seconds)
            [[ $# -ge 2 ]] || die "--lfu-warmup-seconds requires a value"
            LFU_WARMUP_SECONDS="$2"
            shift 2
            ;;
        --lru-warmup-seconds)
            [[ $# -ge 2 ]] || die "--lru-warmup-seconds requires a value"
            LRU_WARMUP_SECONDS="$2"
            shift 2
            ;;
        --arc-warmup-seconds)
            [[ $# -ge 2 ]] || die "--arc-warmup-seconds requires a value"
            ARC_WARMUP_SECONDS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            $target_was_set && die "only one policy selector may be provided"
            TARGET_POLICY="$1"
            target_was_set=true
            shift
            ;;
    esac
done

if [[ "$TARGET_POLICY" != "all" ]] && ! is_supported_policy "$TARGET_POLICY"; then
    die "unsupported policy '$TARGET_POLICY'; expected all, fifo, s3fifo, lfu, lru, or arc"
fi
is_supported_pressure "$PRESSURE_FILTER" || \
    die "unsupported pressure '$PRESSURE_FILTER'; expected all, low, medium, or high"

is_positive_integer "$MEASUREMENT_SECONDS" || \
    die "runtime must be a positive integer number of seconds"
for warmup_value in \
    "$FIFO_WARMUP_SECONDS" "$S3FIFO_WARMUP_SECONDS" "$LFU_WARMUP_SECONDS" \
    "$LRU_WARMUP_SECONDS" "$ARC_WARMUP_SECONDS"; do
    is_positive_integer "$warmup_value" || \
        die "warmup values must be positive integer seconds"
done
[[ "$CGROUP_SIZE" =~ ^[1-9][0-9]*[kKmMgGtTpP]?$ ]] || \
    die "cgroup size must look like 1G, 512M, or a byte count"
[[ "$IOENGINE" =~ ^[a-zA-Z0-9_-]+$ ]] || \
    die "ioengine may contain only letters, digits, '_' and '-'"

if [[ "$TARGET_POLICY" == "all" ]]; then
    selected_policies=("${SUPPORTED_POLICIES[@]}")
else
    selected_policies=("$TARGET_POLICY")
fi

if [[ "$PRESSURE_FILTER" == "all" ]]; then
    selected_pressures=("${SUPPORTED_PRESSURES[@]}")
else
    selected_pressures=("$PRESSURE_FILTER")
fi

emit_fifo_job_config() {
    local pressure="$1"
    local warmup_seconds="$2"
    local measurement_seconds="$3"
    local rate
    rate=$(scale_rate 1100 "$pressure")

    cat <<EOF
[
  {
    "name": "steady_fifo_cold_stream_a",
    "group": "cold",
    "target_policy": "fifo",
    "pressure": "$pressure",
    "intent": "Near-zero reuse stream; FIFO should avoid costly metadata decisions.",
    "filename": "fifo_cold_a.bin",
    "size": "512m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_fifo_cold_stream_b",
    "group": "cold",
    "target_policy": "fifo",
    "pressure": "$pressure",
    "intent": "Independent cold stream to keep reuse low across workers.",
    "filename": "fifo_cold_b.bin",
    "size": "512m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_fifo_cold_stream_c",
    "group": "cold",
    "target_policy": "fifo",
    "pressure": "$pressure",
    "intent": "Independent cold stream to stress eviction throughput.",
    "filename": "fifo_cold_c.bin",
    "size": "512m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_fifo_cold_stream_d",
    "group": "cold",
    "target_policy": "fifo",
    "pressure": "$pressure",
    "intent": "Independent cold stream to minimize temporal locality.",
    "filename": "fifo_cold_d.bin",
    "size": "512m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_fifo_cold_stream_e",
    "group": "cold",
    "target_policy": "fifo",
    "pressure": "$pressure",
    "intent": "Independent cold stream to create steady page-cache churn.",
    "filename": "fifo_cold_e.bin",
    "size": "512m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_fifo_cold_stream_f",
    "group": "cold",
    "target_policy": "fifo",
    "pressure": "$pressure",
    "intent": "Independent cold stream; CPU and tail latency are the main comparison.",
    "filename": "fifo_cold_f.bin",
    "size": "512m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  }
]
EOF
}

emit_s3fifo_job_config() {
    local pressure="$1"
    local warmup_seconds="$2"
    local measurement_seconds="$3"
    local hot_rate
    local cold_rate
    hot_rate=$(scale_rate 3800 "$pressure")
    cold_rate=$(scale_rate 400 "$pressure")

    cat <<EOF
[
  {
    "name": "steady_s3fifo_hot_core",
    "group": "hot",
    "target_policy": "s3fifo",
    "pressure": "$pressure",
    "intent": "Primary Zipf hot core; S3FIFO should retain these pages while cold streams only provide pollution.",
    "numjobs": 2,
    "filename": "s3fifo_hot.bin",
    "size": "160m",
    "rw": "randread",
    "bs": "4k",
    "random_distribution": "zipf:1.35",
    "rate_iops": $hot_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_s3fifo_cold_polluter_a",
    "group": "cold",
    "target_policy": "s3fifo",
    "pressure": "$pressure",
    "intent": "Light cold polluter set; enough to disturb recency without dominating overall tail latency.",
    "numjobs": 3,
    "filename": "s3fifo_cold_a.bin",
    "size": "4g",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $cold_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_s3fifo_cold_polluter_b",
    "group": "cold",
    "target_policy": "s3fifo",
    "pressure": "$pressure",
    "intent": "Second cold region increases pollution dimensionality while keeping hot as the primary group.",
    "numjobs": 3,
    "filename": "s3fifo_cold_b.bin",
    "size": "4g",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $cold_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  }
]
EOF
}

emit_lfu_job_config() {
    local pressure="$1"
    local warmup_seconds="$2"
    local measurement_seconds="$3"
    local hot_rate
    local noise_rate
    hot_rate=$(scale_rate 2400 "$pressure")
    noise_rate=$(scale_rate 1400 "$pressure")

    cat <<EOF
[
  {
    "name": "steady_lfu_hot_frequency",
    "group": "hot",
    "target_policy": "lfu",
    "pressure": "$pressure",
    "intent": "Long warmup builds frequency separation; LFU should keep the hot set.",
    "numjobs": 3,
    "filename": "lfu_hot.bin",
    "size": "96m",
    "rw": "randread",
    "bs": "4k",
    "random_distribution": "zipf:1.50",
    "rate_iops": $hot_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_lfu_noise_medium",
    "group": "noise",
    "target_policy": "lfu",
    "pressure": "$pressure",
    "intent": "Medium noise creates recency pressure but should not outrank hot pages by frequency.",
    "filename": "lfu_noise_medium.bin",
    "size": "384m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $noise_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_lfu_noise_large",
    "group": "noise",
    "target_policy": "lfu",
    "pressure": "$pressure",
    "intent": "Large noise stream keeps page faults active through the measured interval.",
    "filename": "lfu_noise_large.bin",
    "size": "768m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $noise_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  }
]
EOF
}

emit_lru_job_config() {
    local pressure="$1"
    local warmup_seconds="$2"
    local measurement_seconds="$3"
    local recent_rate
    local perturb_rate
    recent_rate=$(scale_rate 1600 "$pressure")
    perturb_rate=$(scale_rate 1600 "$pressure")

    cat <<EOF
[
  {
    "name": "steady_lru_recent_window",
    "group": "recent",
    "target_policy": "lru",
    "pressure": "$pressure",
    "intent": "Moderately skewed recent working set favors simple recency replacement.",
    "numjobs": 4,
    "filename": "lru_recent.bin",
    "size": "192m",
    "rw": "randread",
    "bs": "4k",
    "random_distribution": "zipf:1.15",
    "rate_iops": $recent_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_lru_perturbation",
    "group": "perturb",
    "target_policy": "lru",
    "pressure": "$pressure",
    "intent": "Small perturbation prevents a trivial all-hot fit while keeping recency dominant.",
    "filename": "lru_perturb.bin",
    "size": "256m",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $perturb_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  }
]
EOF
}

emit_arc_job_config() {
    local pressure="$1"
    local warmup_seconds="$2"
    local measurement_seconds="$3"
    local frequent_rate
    local recent_rate
    local cold_rate
    frequent_rate=$(scale_rate 1900 "$pressure")
    recent_rate=$(scale_rate 1900 "$pressure")
    cold_rate=$(scale_rate 1200 "$pressure")

    cat <<EOF
[
  {
    "name": "steady_arc_frequent",
    "group": "frequent",
    "target_policy": "arc",
    "pressure": "$pressure",
    "intent": "Frequent component tests ARC's ability to preserve repeated pages.",
    "numjobs": 2,
    "filename": "arc_frequent.bin",
    "size": "96m",
    "rw": "randread",
    "bs": "4k",
    "random_distribution": "zipf:1.45",
    "rate_iops": $frequent_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_arc_recent",
    "group": "recent",
    "target_policy": "arc",
    "pressure": "$pressure",
    "intent": "Recent component gives ARC a recency signal in parallel with frequency.",
    "numjobs": 2,
    "filename": "arc_recent.bin",
    "size": "192m",
    "rw": "randread",
    "bs": "4k",
    "random_distribution": "zipf:1.18",
    "rate_iops": $recent_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  },
  {
    "name": "steady_arc_cold_background",
    "group": "cold",
    "target_policy": "arc",
    "pressure": "$pressure",
    "intent": "Cold background verifies that ARC balances recency/frequency under pollution.",
    "numjobs": 2,
    "filename": "arc_cold.bin",
    "size": "4g",
    "rw": "randread",
    "bs": "4k",
    "rate_iops": $cold_rate,
    "runtime": $measurement_seconds,
    "ramp_time": $warmup_seconds
  }
]
EOF
}

emit_job_config() {
    local policy="$1"
    local pressure="$2"
    local warmup_seconds="$3"
    local measurement_seconds="$4"

    case "$policy" in
        fifo) emit_fifo_job_config "$pressure" "$warmup_seconds" "$measurement_seconds" ;;
        s3fifo) emit_s3fifo_job_config "$pressure" "$warmup_seconds" "$measurement_seconds" ;;
        lfu) emit_lfu_job_config "$pressure" "$warmup_seconds" "$measurement_seconds" ;;
        lru) emit_lru_job_config "$pressure" "$warmup_seconds" "$measurement_seconds" ;;
        arc) emit_arc_job_config "$pressure" "$warmup_seconds" "$measurement_seconds" ;;
        *) die "cannot generate jobs for policy '$policy'" ;;
    esac
}

total_rate_iops() {
    local policy="$1"
    local pressure="$2"
    case "$policy" in
        fifo)
            echo $((6 * $(scale_rate 1100 "$pressure")))
            ;;
        s3fifo)
            echo $((2 * $(scale_rate 3800 "$pressure") + 6 * $(scale_rate 400 "$pressure")))
            ;;
        lfu)
            echo $((3 * $(scale_rate 2400 "$pressure") + 2 * $(scale_rate 1400 "$pressure")))
            ;;
        lru)
            echo $((4 * $(scale_rate 1600 "$pressure") + $(scale_rate 1600 "$pressure")))
            ;;
        arc)
            echo $((2 * $(scale_rate 1900 "$pressure") + 2 * $(scale_rate 1900 "$pressure") + 2 * $(scale_rate 1200 "$pressure")))
            ;;
        *) die "cannot compute rate for policy '$policy'" ;;
    esac
}

primary_rate_iops() {
    local policy="$1"
    local pressure="$2"
    case "$policy" in
        fifo) echo $((6 * $(scale_rate 1100 "$pressure"))) ;;
        s3fifo) echo $((2 * $(scale_rate 3800 "$pressure"))) ;;
        lfu) echo $((3 * $(scale_rate 2400 "$pressure"))) ;;
        lru) echo $((4 * $(scale_rate 1600 "$pressure"))) ;;
        arc) echo $((2 * $(scale_rate 1900 "$pressure") + 2 * $(scale_rate 1900 "$pressure"))) ;;
        *) die "cannot compute primary rate for policy '$policy'" ;;
    esac
}

polluter_rate_iops() {
    local policy="$1"
    local pressure="$2"
    case "$policy" in
        fifo) echo 0 ;;
        s3fifo) echo $((6 * $(scale_rate 400 "$pressure"))) ;;
        lfu) echo $((2 * $(scale_rate 1400 "$pressure"))) ;;
        lru) echo "$(scale_rate 1600 "$pressure")" ;;
        arc) echo $((2 * $(scale_rate 1200 "$pressure"))) ;;
        *) die "cannot compute polluter rate for policy '$policy'" ;;
    esac
}

rate_share_permille() {
    local part="$1"
    local total="$2"
    if [[ "$total" -eq 0 ]]; then
        echo "0.000"
        return 0
    fi
    awk -v part="$part" -v total="$total" 'BEGIN { printf "%.3f", part / total }'
}

primary_group_for_policy() {
    case "$1" in
        fifo) echo "cold" ;;
        s3fifo) echo "hot" ;;
        lfu) echo "hot" ;;
        lru) echo "recent" ;;
        arc) echo "frequent,recent" ;;
        *) die "no primary group for policy '$1'" ;;
    esac
}

polluter_groups_for_policy() {
    case "$1" in
        fifo) echo "none" ;;
        s3fifo) echo "cold" ;;
        lfu) echo "noise" ;;
        lru) echo "perturb" ;;
        arc) echo "cold" ;;
        *) die "no polluter group for policy '$1'" ;;
    esac
}

success_metric_for_policy() {
    case "$1" in
        fifo) echo "cold_cpu_per_io,cold_mean_latency,cold_p99_latency" ;;
        s3fifo) echo "hot_mean_latency,hot_p99_latency,hot_refault_delta" ;;
        lfu) echo "hot_mean_latency,hot_p99_latency,frequency_retention" ;;
        lru) echo "recent_mean_latency,recent_p99_latency" ;;
        arc) echo "frequent_recent_mean_latency,frequent_recent_p99_latency,overall_balance" ;;
        *) die "no success metric for policy '$1'" ;;
    esac
}

working_set_for_policy() {
    case "$1" in
        fifo) echo "cold=6x512M" ;;
        s3fifo) echo "hot=160M,cold=2x4G/6jobs-light" ;;
        lfu) echo "hot=96M,noise=384M+768M" ;;
        lru) echo "recent=192M,perturb=256M" ;;
        arc) echo "frequent=96M,recent=192M,cold=4G/2jobs-light" ;;
        *) die "no working-set description for policy '$1'" ;;
    esac
}

design_intent_for_policy() {
    case "$1" in
        fifo)
            echo "Cold random streams are the primary workload; compare metadata overhead and tail latency under miss-heavy churn."
            ;;
        s3fifo)
            echo "Hot Zipf core is primary and cold streams are light polluters; test S3FIFO hot-page protection without polluter-dominated tails."
            ;;
        lfu)
            echo "Long warmup creates a stable frequency hierarchy; light noise tests whether frequency beats short-term recency."
            ;;
        lru)
            echo "Recent-window locality dominates with light perturbation; test simple recency behavior without sequential readahead."
            ;;
        arc)
            echo "Frequent and recent groups are primary with light cold pollution; test adaptive recency/frequency balancing."
            ;;
        *) die "no design intent for policy '$1'" ;;
    esac
}

mkdir -p "$OUTPUT_DIR"

manifest_tmp=$(mktemp "$OUTPUT_DIR/.manifest.XXXXXX")
trap 'rm -f "$manifest_tmp"' EXIT
printf 'benchmark_id\ttarget_policy\tprofile\tpressure\truntime_seconds\twarmup_seconds\tmeasurement_seconds\tcgroup_size\tioengine\ttotal_rate_iops\tprimary_group\tpolluter_groups\tsuccess_metric\tprimary_rate_iops\tpolluter_rate_iops\tprimary_iops_share\tpolluter_iops_share\tworking_set\tdesign_intent\tjob_config\n' > "$manifest_tmp"

generated_count=0
for policy in "${selected_policies[@]}"; do
    profile=$(profile_for_policy "$policy")
    warmup_seconds=$(policy_warmup_seconds "$policy")
    runtime_seconds=$((warmup_seconds + MEASUREMENT_SECONDS))
    working_set=$(working_set_for_policy "$policy")
    design_intent=$(design_intent_for_policy "$policy")
    primary_group=$(primary_group_for_policy "$policy")
    polluter_groups=$(polluter_groups_for_policy "$policy")
    success_metric=$(success_metric_for_policy "$policy")

    for pressure in "${selected_pressures[@]}"; do
        benchmark_id="${policy}_${profile}_${pressure}"
        output_name="${benchmark_id}.jobs.json"
        output_path="$OUTPUT_DIR/$output_name"
        output_tmp=$(mktemp "$OUTPUT_DIR/.${output_name}.XXXXXX")
        total_iops=$(total_rate_iops "$policy" "$pressure")
        primary_iops=$(primary_rate_iops "$policy" "$pressure")
        polluter_iops=$(polluter_rate_iops "$policy" "$pressure")
        primary_share=$(rate_share_permille "$primary_iops" "$total_iops")
        polluter_share=$(rate_share_permille "$polluter_iops" "$total_iops")

        emit_job_config "$policy" "$pressure" "$warmup_seconds" "$MEASUREMENT_SECONDS" > "$output_tmp"
        mv -f "$output_tmp" "$output_path"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$benchmark_id" "$policy" "$profile" "$pressure" \
            "$runtime_seconds" "$warmup_seconds" "$MEASUREMENT_SECONDS" \
            "$CGROUP_SIZE" "$IOENGINE" "$total_iops" "$primary_group" \
            "$polluter_groups" "$success_metric" "$primary_iops" \
            "$polluter_iops" "$primary_share" "$polluter_share" \
            "$working_set" "$design_intent" "$output_name" >> "$manifest_tmp"
        generated_count=$((generated_count + 1))
        echo "[Generated] $output_path"
    done
done

mv -f "$manifest_tmp" "$OUTPUT_DIR/manifest.tsv"
trap - EXIT

echo "[Generated] $OUTPUT_DIR/manifest.tsv"
echo "[Done] Generated $generated_count fio benchmark definition(s)."
