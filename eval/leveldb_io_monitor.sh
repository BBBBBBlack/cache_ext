# Shared Twitter/YCSB 30-second completed-op/cgroup snapshot wrapper.
# Independent cgroup polling is optional when phase-aligned snapshots exist.
resolve_memory_poll() {
    case "${MEMORY_POLL:-auto}" in
        auto) MEMORY_POLL_ENABLED=false ;;
        true) MEMORY_POLL_ENABLED="$TEST_MEMORY" ;;
        false) MEMORY_POLL_ENABLED=false ;;
        *) echo "[Error] memory_poll must be auto, true or false" >&2; return 2 ;;
    esac
}

check_leveldb_io_binary() {
    if [ "$TEST_MEMORY" = true ] &&
       ! "$YCSB_PATH/build/run_leveldb" --diagnostics-version 2>/dev/null | grep -qx 'benchmark-snapshots-v1'; then
        echo "[Error] Rebuild LevelDB/YCSB with benchmark-only snapshots first:" >&2
        echo "cmake -S $YCSB_PATH -B $YCSB_PATH/build -DCMAKE_BUILD_TYPE=Release" >&2
        echo "cmake --build $YCSB_PATH/build --target run_leveldb init_leveldb -j4" >&2
        return 1
    fi
}

# $1 stage, $2 filename prefix (includes cluster/size), $3 mode; remaining: bench args.
run_with_leveldb_io() {
    local stage="$1" prefix="$2" mode="$3"
    shift 3
    local io_log="${prefix}_leveldb_io_${mode}_${stage}.jsonl"
    local window_csv="${prefix}_io_windows_${mode}_${stage}.csv"
    local throughput_log="${prefix}_throughput_${mode}_${stage}.log"
    if [ -f "$io_log" ]; then
        mv -f -- "$io_log" "${io_log}.previous"
    fi
    echo "[Info] Aligned 30s completed-ops / cgroup CPU / IO / memory / reclaim: $io_log"
    local status=0
    PYTHONUNBUFFERED=1 "${BASE_CMD[@]}" --leveldb-io-log "$io_log" "$@" || status=$?
    if [ -s "$io_log" ]; then
        if ! python3 "$BASE_DIR/scripts/leveldb_io_windows.py" "$io_log" \
            --output "$window_csv" --throughput-log "$throughput_log" --stage-label "$stage"; then
            if [ "$status" -eq 0 ]; then status=1; fi
        fi
    else
        echo "[Error] Missing benchmark snapshots: $io_log" >&2
        if [ "$status" -eq 0 ]; then status=1; fi
    fi
    return "$status"
}
